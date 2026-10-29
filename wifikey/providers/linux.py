"""Linux 数据源（NetworkManager keyfile / wpa_supplicant 配置）。"""

from __future__ import annotations

import configparser
import glob
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from wifikey.models import WifiNetwork
from wifikey.providers.base import Provider

NM_DIR = "/etc/NetworkManager/system-connections"

_KEY_MGMT_SECURITY = {
    "none": "Open",
    "wpa-psk": "WPA-Personal",
    "wpa-eap": "WPA-Enterprise",
    "sae": "WPA3-SAE",
    "owe": "OWE (Enhanced Open)",
    "static-wep": "WEP",
    "wep": "WEP",
}


def _unquote(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def parse_nm_keyfile(text: str) -> WifiNetwork | None:
    """解析 NetworkManager 的 .nmconnection keyfile。"""
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    try:
        parser.read_string(text)
    except configparser.Error:
        return None

    def get(section: str, option: str) -> str | None:
        if parser.has_option(section, option):
            return _unquote(parser.get(section, option))
        return None

    ssid = get("wifi", "ssid") or get("802-11-wireless", "ssid")
    if not ssid:
        return None

    key_mgmt = (get("wifi-security", "key-mgmt") or get("802-11-wireless-security", "key-mgmt") or "none").lower()
    psk = get("wifi-security", "psk") or get("802-11-wireless-security", "psk")
    psk_flags = get("wifi-security", "psk-flags") or "0"
    if psk_flags == "1":
        psk = None  # 由密钥代理保存，keyfile 中没有明文

    if key_mgmt == "static-wep":
        psk = psk or get("wifi-security", "wep-key0")

    cipher = get("wifi-security", "pairwise") or get("802-11-wireless-security", "pairwise")
    hidden = (get("wifi", "hidden") or get("802-11-wireless", "hidden") or "false").lower() == "true"

    return WifiNetwork(
        ssid=ssid,
        password=psk,
        security=_KEY_MGMT_SECURITY.get(key_mgmt, key_mgmt or "Unknown"),
        cipher=cipher.upper() if cipher else None,
        auth=key_mgmt,
        connection_mode="auto",
        hidden=hidden,
        source="networkmanager-keyfile",
        extra={"path": NM_DIR},
    )


_WPA_BLOCK = re.compile(r"network\s*=\s*\{(.*?)\}", re.S)
_WPA_KV = re.compile(r'(\w+)\s*=\s*("(?:\\.|[^"])*"|[^\s#]+)')


def parse_wpa_supplicant(text: str) -> list[WifiNetwork]:
    """解析 wpa_supplicant.conf 中的 network 块。"""
    networks: list[WifiNetwork] = []
    for block in _WPA_BLOCK.findall(text):
        values: dict[str, str] = {}
        for key, value in _WPA_KV.findall(block):
            values[key] = _unquote(value) or ""
        ssid = values.get("ssid")
        if not ssid:
            continue
        key_mgmt = (values.get("key_mgmt") or "").upper()
        psk = values.get("psk")
        if key_mgmt in ("NONE", "OWE"):
            security = "OWE (Enhanced Open)" if key_mgmt == "OWE" else "Open"
            psk = None
        elif key_mgmt.startswith("WPA-PSK-SHA256") or key_mgmt.startswith("SAE"):
            security = "WPA3-SAE" if "SAE" in key_mgmt else "WPA2-Personal"
        elif key_mgmt.startswith("WPA"):
            security = "WPA-Personal"
        elif key_mgmt.startswith("WEP"):
            security = "WEP"
        else:
            security = "Unknown"

        networks.append(
            WifiNetwork(
                ssid=ssid,
                password=psk or None,
                security=security,
                auth=key_mgmt or None,
                cipher=values.get("pairwise") or None,
                connection_mode="auto",
                hidden=values.get("scan_ssid") == "1",
                source="wpa_supplicant",
                extra={"path": "wpa_supplicant.conf"},
            )
        )
    return networks


def parse_nmcli_connection_names(output: str) -> list[str]:
    """解析 ``nmcli -t -f NAME,TYPE connection show`` 中的无线连接名。"""
    names: list[str] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        # nmcli 会把名称里的 ":" 转义成 "\:"，因此从最后一个 ":" 处切分类型
        parts = line.rsplit(":", 1)
        if len(parts) != 2:
            continue
        name, ctype = parts[0], parts[1]
        if ctype.strip() == "802-11-wireless":
            names.append(name.replace("\\:", ":"))
    return names


class LinuxProvider(Provider):
    name = "linux"
    display_name = "Linux (NetworkManager / wpa_supplicant)"
    note = "读取 /etc/NetworkManager 与 wpa_supplicant 配置通常需要 root 权限。"

    def available(self) -> tuple[bool, str]:
        if not sys.platform.startswith("linux"):
            return False, "当前系统不是 Linux"
        return True, ""

    def list_networks(self, include_passwords: bool = True) -> list[WifiNetwork]:
        networks: list[WifiNetwork] = []
        networks.extend(self._from_networkmanager(include_passwords))
        networks.extend(self._from_wpa_supplicant(include_passwords))

        if not networks and include_passwords:
            # 没权限读配置时，至少给出连接名称
            for name in self._nmcli_connection_names():
                networks.append(
                    WifiNetwork(
                        ssid=name,
                        password=None,
                        security="Unknown",
                        source="nmcli",
                        extra={"hint": "需要 root 权限才能读取密码（sudo 重新运行）"},
                    )
                )

        # 同一 SSID 去重，优先保留能读到密码的那条
        best: dict[str, WifiNetwork] = {}
        for net in networks:
            key = net.ssid.casefold()
            current = best.get(key)
            if current is None or (not current.has_password and net.has_password):
                best[key] = net
        result = sorted(best.values(), key=lambda n: n.ssid.casefold())
        return result

    def current_ssid(self) -> str | None:
        if shutil.which("iwgetid"):
            try:
                proc = subprocess.run(["iwgetid", "-r"], capture_output=True, timeout=5)
                value = proc.stdout.decode("utf-8", "replace").strip()
                if value:
                    return value
            except Exception:
                pass
        if shutil.which("nmcli"):
            try:
                proc = subprocess.run(
                    ["nmcli", "-t", "-f", "TYPE,STATE,CONNECTION", "device", "status"],
                    capture_output=True,
                    timeout=5,
                )
                for line in proc.stdout.decode("utf-8", "replace").splitlines():
                    parts = line.split(":")
                    if len(parts) == 3 and parts[0] == "wifi" and parts[1] == "connected":
                        return parts[2] or None
            except Exception:
                pass
        return None

    # ------------------------------------------------------------------ 内部

    def _from_networkmanager(self, include_passwords: bool) -> list[WifiNetwork]:
        networks: list[WifiNetwork] = []
        paths = sorted(glob.glob(os.path.join(NM_DIR, "*")))
        for path in paths:
            try:
                text = Path(path).read_text(encoding="utf-8", errors="replace")
            except PermissionError:
                continue
            except OSError:
                continue
            net = parse_nm_keyfile(text)
            if not net:
                continue
            net.extra["path"] = path
            if not include_passwords:
                net.password = None
            networks.append(net)
        return networks

    def _from_wpa_supplicant(self, include_passwords: bool) -> list[WifiNetwork]:
        patterns = [
            "/etc/wpa_supplicant/wpa_supplicant.conf",
            "/etc/wpa_supplicant/wpa_supplicant-*.conf",
            os.path.expanduser("~/.config/wpa_supplicant.conf"),
        ]
        networks: list[WifiNetwork] = []
        seen_paths: set[str] = set()
        for pattern in patterns:
            for path in glob.glob(pattern):
                if path in seen_paths or not os.access(path, os.R_OK):
                    continue
                seen_paths.add(path)
                try:
                    text = Path(path).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for net in parse_wpa_supplicant(text):
                    net.extra["path"] = path
                    if not include_passwords:
                        net.password = None
                    networks.append(net)
        return networks

    def _nmcli_connection_names(self) -> list[str]:
        if not shutil.which("nmcli"):
            return []
        try:
            proc = subprocess.run(
                ["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"],
                capture_output=True,
                timeout=15,
            )
        except Exception:
            return []
        return parse_nmcli_connection_names(proc.stdout.decode("utf-8", "replace"))
