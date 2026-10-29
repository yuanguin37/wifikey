"""Windows 数据源。

两条路径：
1. 首选 ``netsh wlan export profile ... key=clear`` 导出 XML，再解析 XML。
   XML 的标签名与系统语言无关，因此中文/英文/日文系统都能稳定解析。
2. 若导出失败（极端字符、组策略限制等），退回解析 ``netsh wlan show profile``
   文本输出，兼容英文与中文标签。

整个过程只读取配置，不修改、不删除任何 WiFi 配置。
"""

from __future__ import annotations

import ctypes
import locale
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET

from wifikey.models import WifiNetwork
from wifikey.providers.base import Provider

CREATE_NO_WINDOW = 0x08000000

_AUTH_LABEL = {
    "SSID name": "ssid",
    "SSID 名称": "ssid",
    "Authentication": "auth",
    "身份验证": "auth",
    "Cipher": "cipher",
    "密码": "cipher",
    "加密": "cipher",
    "Security key": "key_present",
    "安全密钥": "key_present",
    "Key Content": "key_content",
    "关键内容": "key_content",
    "Connection mode": "mode",
    "连接模式": "mode",
}

_CIPHER_DISPLAY = {
    "AES": "CCMP",
    "CCMP": "CCMP",
    "GCMP": "GCMP",
    "TKIP": "TKIP",
    "AES-CCMP": "CCMP",
    "NONE": "None",
}


def _decode(data: bytes) -> str:
    for enc in ("utf-8", locale.getpreferredencoding(False), "cp936", "cp437"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def run_netsh(args: list[str], timeout: int = 40) -> tuple[int, str]:
    """执行 netsh 命令并返回 (退出码, 文本输出)。"""
    flags = CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        proc = subprocess.run(
            ["netsh", *args],
            capture_output=True,
            timeout=timeout,
            creationflags=flags,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, f"执行 netsh 失败: {exc}"
    return proc.returncode, _decode(proc.stdout + proc.stderr)


def _short_path(path: str) -> str:
    """把含空格的路径转换为 8.3 短路径，避免 netsh 的参数解析问题。"""
    if sys.platform != "win32" or " " not in path:
        return path
    try:
        buf = ctypes.create_unicode_buffer(1024)
        ctypes.windll.kernel32.GetShortPathNameW(path, buf, 1024)
        return buf.value or path
    except Exception:
        return path


def friendly_security(auth: str | None, use_onex: bool = False, has_key: bool = False) -> str:
    """把 Windows 的 auth 标签转换为可读的安全类型。"""
    raw = (auth or "").strip()
    norm = raw.upper().replace(" ", "").replace("-", "").replace("_", "")
    if norm in ("", "OPEN", "NONE"):
        return "Open"
    if norm == "WEP":
        return "WEP"
    if norm.startswith("WPA3"):
        return "WPA3-SAE" if "SAE" in norm else "WPA3-Personal"
    for prefix in ("WPA2", "WPA"):
        if norm.startswith(prefix):
            if use_onex:
                return f"{prefix}-Enterprise"
            if "PSK" in norm or has_key:
                return f"{prefix}-Personal"
            return f"{prefix}-Enterprise"
    if norm.startswith("OWE"):
        return "OWE (Enhanced Open)"
    return raw or "Unknown"


def friendly_cipher(cipher: str | None) -> str | None:
    if not cipher:
        return None
    value = cipher.strip()
    if value.lower() in ("none", ""):
        return None
    return _CIPHER_DISPLAY.get(value.upper(), value)


def parse_profile_xml(text: str) -> WifiNetwork | None:
    """解析单个 WLANProfile XML，返回网络对象。"""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None

    def first(tag: str) -> str | None:
        node = root.find(f".//{{*}}{tag}")
        return node.text.strip() if node is not None and node.text else None

    def all_tags(tag: str) -> list[str]:
        return [(n.text or "").strip() for n in root.findall(f".//{{*}}{tag}")]

    profile_name = first("name")
    ssid = None
    ssid_nodes = root.findall(".//{*}SSID")
    for node in ssid_nodes:
        name = node.find("{*}name")
        if name is not None and name.text:
            ssid = name.text.strip()
            break
        hex_node = node.find("{*}hex")
        if hex_node is not None and hex_node.text:
            try:
                ssid = bytes.fromhex(hex_node.text.strip()).decode("utf-8", "replace")
            except ValueError:
                ssid = None
            break

    if not ssid:
        ssid = profile_name or "未知网络"

    auth = first("authentication")
    cipher = first("encryption")
    key_material = first("keyMaterial")
    protected = (first("protected") or "").lower() == "true"
    use_onex = (first("useOneX") or "").lower() == "true"
    connection_mode = first("connectionMode")
    hidden = (first("nonBroadcast") or "").lower() == "true"
    key_type = first("keyType")
    # 过渡模式可能同时存在 WPA2PSK / WPA3SAE 等多个 <authentication>，取最强的那个
    auth_tags = all_tags("authentication")
    if auth_tags:
        def rank(tag: str) -> int:
            norm = tag.upper().replace(" ", "").replace("-", "").replace("_", "")
            if "SAE" in norm:
                return 0
            if norm.startswith("WPA3"):
                return 1
            if norm.startswith("WPA2"):
                return 2
            if norm.startswith("WPA"):
                return 3
            if "OWE" in norm:
                return 4
            if "WEP" in norm:
                return 5
            return 6

        auth = min(auth_tags, key=rank)

    password = None
    if key_material and not protected and key_type != "WPAPSK":
        password = key_material

    return WifiNetwork(
        ssid=ssid,
        password=password,
        security=friendly_security(auth, use_onex=use_onex, has_key=bool(password)),
        cipher=friendly_cipher(cipher),
        auth=auth,
        connection_mode="auto" if connection_mode == "auto" else ("manual" if connection_mode else None),
        hidden=hidden,
        source="netsh-xml",
        extra={
            "profile": profile_name or ssid,
            "protected": protected,
            "key_type": key_type,
        },
    )


def parse_profile_text(output: str, profile_name: str = "") -> WifiNetwork | None:
    """解析 ``netsh wlan show profile`` 的文本输出（英文/中文标签）。"""
    ssid = None
    auth = None
    cipher = None
    key_content = None
    key_present = False
    mode = None
    for line in output.splitlines():
        if ":" not in line:
            continue
        label, value = line.split(":", 1)
        key = _AUTH_LABEL.get(label.strip())
        if not key:
            continue
        value = value.strip().strip('"“”\'‘’')
        if key == "ssid" and ssid is None:
            ssid = value
        elif key == "auth" and auth is None:
            auth = value
        elif key == "cipher" and cipher is None:
            cipher = value
        elif key == "key_present":
            key_present = bool(value) and value not in ("无", "不存在", "Absent")
        elif key == "key_content" and key_content is None:
            key_content = value
        elif key == "mode" and mode is None:
            mode = "auto" if value.lower() in ("connect automatically", "自动连接") else "manual"

    if not ssid:
        ssid = profile_name
    if not ssid:
        return None

    password = key_content if key_content and key_content != "无" else None
    return WifiNetwork(
        ssid=ssid,
        password=password,
        security=friendly_security(auth, has_key=key_present),
        cipher=friendly_cipher(cipher),
        auth=auth,
        connection_mode=mode,
        source="netsh-text",
        extra={"profile": profile_name or ssid, "key_present": key_present},
    )


def parse_profile_names(output: str) -> list[str]:
    """从 ``netsh wlan show profiles`` 输出中提取配置名。"""
    names: list[str] = []
    for line in output.splitlines():
        if ":" not in line:
            continue
        label, value = line.split(":", 1)
        label = label.strip()
        if label.lower() not in ("all user profile", "所有用户配置文件"):
            continue
        name = value.strip()
        if not name or name in ("<None>", "<无>", "无"):
            continue
        names.append(name)
    return names


def parse_current_ssid(output: str) -> str | None:
    """从 ``netsh wlan show interfaces`` 输出中提取当前连接的 SSID。"""
    for line in output.splitlines():
        if ":" not in line:
            continue
        label, value = line.split(":", 1)
        if label.strip().lower() != "ssid":
            continue
        value = value.strip()
        if value:
            return value
    return None


class WindowsProvider(Provider):
    name = "windows"
    display_name = "Windows (netsh / WLANProfile XML)"
    note = "密码来自本机已保存的 WLAN 配置文件，无需管理员权限即可读取当前用户配置。"

    def available(self) -> tuple[bool, str]:
        if sys.platform != "win32":
            return False, "当前系统不是 Windows"
        if not shutil.which("netsh"):
            return False, "未找到 netsh 命令"
        return True, ""

    def list_networks(self, include_passwords: bool = True) -> list[WifiNetwork]:
        networks = self._from_xml_export(include_passwords)
        # 补全导出失败/被跳过的配置
        known = {n.extra.get("profile", n.ssid).casefold() for n in networks}
        for name in self._profile_names():
            if name.casefold() in known:
                continue
            net = self._show_profile(name, include_passwords=include_passwords)
            if net:
                networks.append(net)

        networks.sort(key=lambda n: n.ssid.casefold())
        return networks

    def current_ssid(self) -> str | None:
        code, out = run_netsh(["wlan", "show", "interfaces"], timeout=15)
        if code != 0:
            return None
        return parse_current_ssid(out)

    # ------------------------------------------------------------------ 内部

    def _profile_names(self) -> list[str]:
        code, out = run_netsh(["wlan", "show", "profiles"])
        return parse_profile_names(out) if code == 0 else []

    def _from_xml_export(self, include_passwords: bool = True) -> list[WifiNetwork]:
        tmp = tempfile.mkdtemp(prefix="wifikey_")
        try:
            folder = _short_path(tmp)
            args = ["wlan", "export", "profile", f"folder={folder}"]
            if include_passwords:
                args.append("key=clear")
            code, out = run_netsh(args, timeout=60)
            networks: list[WifiNetwork] = []
            for path in sorted(Path(tmp).glob("*.xml")):
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                net = parse_profile_xml(text)
                if net:
                    if not include_passwords:
                        net.password = None
                    networks.append(net)
            if not networks and code != 0:
                return []
            return networks
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def _show_profile(self, name: str, include_passwords: bool) -> WifiNetwork | None:
        args = ["wlan", "show", "profile", f"name={name}"]
        if include_passwords:
            args.append("key=clear")
        code, out = run_netsh(args)
        if code != 0:
            return None
        return parse_profile_text(out, profile_name=name)

    def _from_text_all(self, include_passwords: bool) -> list[WifiNetwork]:
        networks: list[WifiNetwork] = []
        for name in self._profile_names():
            net = self._show_profile(name, include_passwords)
            if net:
                networks.append(net)
        networks.sort(key=lambda n: n.ssid.casefold())
        return networks
