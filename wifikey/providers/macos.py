"""macOS 数据源（Keychain + networksetup）。"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys

from wifikey.models import WifiNetwork
from wifikey.providers.base import Provider

PLIST_PATH = "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"


def _run(args: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return proc.returncode, proc.stdout.decode("utf-8", "replace").strip()


def parse_hardware_ports(text: str) -> str | None:
    """从 ``networksetup -listallhardwareports`` 中找出 Wi-Fi 设备名。"""
    blocks = re.split(r"\n\s*\n", text)
    for block in blocks:
        lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
        port = device = None
        for line in lines:
            if line.lower().startswith("hardware port:"):
                port = line.split(":", 1)[1].strip().lower()
            elif line.lower().startswith("device:"):
                device = line.split(":", 1)[1].strip()
        if device and port and port in ("wi-fi", "airport"):
            return device
    return None


def parse_preferred_networks(text: str) -> list[str]:
    """``networksetup -listpreferredwirelessnetworks`` 输出解析。"""
    names: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.lower().startswith(("preferred networks", "preferred networks on")):
            continue
        if line.endswith(":") and "preferred" in line.lower():
            continue
        names.append(line)
    return names


def _security_display(value: str | None) -> str:
    if not value:
        return "Unknown"
    norm = value.lower()
    if "wpa3" in norm:
        return "WPA3-SAE" if "personal" in norm else "WPA3-Enterprise"
    if "wpa2" in norm:
        return "WPA2-Personal" if "personal" in norm else "WPA2-Enterprise"
    if "wpa" in norm:
        return "WPA-Personal" if "personal" in norm else "WPA-Enterprise"
    if "wep" in norm:
        return "WEP"
    if "open" in norm or "none" in norm:
        return "Open"
    return value


def parse_airport_plist(payload: str) -> dict[str, str]:
    """从机场偏好 plist（JSON 形式）中尽量提取 SSID -> 安全类型。"""
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return {}
    result: dict[str, str] = {}

    def walk(node: object) -> None:
        if isinstance(node, dict):
            ssid = None
            for key in ("SSID", "SSIDString", "_name"):
                value = node.get(key)
                if isinstance(value, str) and value:
                    ssid = value
                    break
            if isinstance(node.get("SecurityType"), str):
                if ssid:
                    result.setdefault(ssid, _security_display(node["SecurityType"]))
            for key, value in node.items():
                if isinstance(key, str) and key.startswith(("SSID_", "wifi.network.")) and isinstance(value, dict):
                    inner = value.get("SSID") or value.get("SSIDString")
                    if isinstance(inner, str):
                        sec = value.get("SecurityType")
                        result.setdefault(inner, _security_display(sec if isinstance(sec, str) else None))
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    return result


class MacOSProvider(Provider):
    name = "macos"
    display_name = "macOS (Keychain / networksetup)"
    note = "首次读取某个网络的密码时，系统可能弹出钥匙串授权对话框。"

    def available(self) -> tuple[bool, str]:
        if sys.platform != "darwin":
            return False, "当前系统不是 macOS"
        if not shutil.which("security"):
            return False, "未找到 security 命令"
        return True, ""

    def list_networks(self, include_passwords: bool = True) -> list[WifiNetwork]:
        device = self._wifi_device()
        names = self._preferred_networks(device) if device else []
        security_map = self._security_map()
        if not names:
            names = sorted(security_map)

        networks: list[WifiNetwork] = []
        for name in names:
            password = self._keychain_password(name) if include_passwords else None
            networks.append(
                WifiNetwork(
                    ssid=name,
                    password=password,
                    security=security_map.get(name, "Unknown"),
                    auth=None,
                    connection_mode="auto",
                    source="macos-keychain",
                    extra={"device": device},
                )
            )
        networks.sort(key=lambda n: n.ssid.casefold())
        return networks

    def current_ssid(self) -> str | None:
        device = self._wifi_device()
        if not device:
            return None
        code, out = _run(["networksetup", "-getairportnetwork", device], timeout=10)
        if code != 0:
            return None
        if ":" in out:
            value = out.split(":", 1)[1].strip()
            if value and "not associated" not in value.lower():
                return value
        return None

    # ------------------------------------------------------------------ 内部

    def _wifi_device(self) -> str | None:
        code, out = _run(["networksetup", "-listallhardwareports"], timeout=10)
        if code != 0:
            return None
        return parse_hardware_ports(out)

    def _preferred_networks(self, device: str) -> list[str]:
        code, out = _run(["networksetup", "-listpreferredwirelessnetworks", device], timeout=15)
        if code != 0:
            return []
        return parse_preferred_networks(out)

    def _keychain_password(self, ssid: str) -> str | None:
        for label in ("AirPort network password", "Wi-Fi network password"):
            code, out = _run(
                ["security", "find-generic-password", "-D", label, "-a", ssid, "-w"],
                timeout=30,
            )
            if code == 0 and out:
                return out
        return None

    def _security_map(self) -> dict[str, str]:
        if not shutil.which("plutil"):
            return {}
        code, out = _run(["plutil", "-convert", "json", "-o", "-", PLIST_PATH], timeout=20)
        if code != 0 or not out:
            return {}
        return parse_airport_plist(out)
