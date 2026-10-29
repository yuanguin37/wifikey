"""周围 WiFi 网络扫描（只读被动扫描）。

仅列出无线网卡当前可见的网络——与系统 WiFi 面板中看到的列表相同——
并对其加密类型、信道分布做环境安全评估。

能力边界：
- 不抓包、不创建热点、不连接、不破解任何网络；
- 扫描结果只包含 AP 主动广播的公开信息（SSID / BSSID / 信号 / 信道 / 加密类型）；
- 无法也绝不尝试获取未保存网络的密码。
"""

from __future__ import annotations

import json as _json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from wifikey.models import Finding, ScanNetwork, WifiNetwork
from wifikey.providers.windows import run_netsh

AIRPORT_BIN = (
    "/System/Library/PrivateFrameworks/Apple80211.framework"
    "/Versions/Current/Resources/airport"
)

# --------------------------------------------------------------------------- 基础工具


def band_of_channel(channel: int | None, freq_mhz: int | None = None) -> str:
    """由频率或信道号推断频段。频率优先（6GHz 信道号与 2.4G 有歧义）。"""
    if freq_mhz:
        if freq_mhz <= 3000:
            return "2.4 GHz"
        if freq_mhz < 5925:
            return "5 GHz"
        return "6 GHz"
    if channel is None:
        return ""
    if 1 <= channel <= 14:
        return "2.4 GHz"
    if 15 <= channel <= 200:
        return "5 GHz"
    if channel > 200:
        return "6 GHz"
    return ""


def rssi_to_percent(rssi: int) -> int:
    """把 dBm（约 -100 ~ -30）换算成 0-100 的信号百分比。"""
    return max(0, min(100, 2 * (rssi + 100)))


def normalize_security(raw: str, cipher: str | None = None) -> str:
    """把各平台的安全描述归一化为统一显示（WPA2-Personal / WPA3-SAE / Open …）。"""
    text = (raw or "").strip()
    cipher_text = (cipher or "").strip()
    compact = re.sub(r"[\s_.\-]+", "", text).lower()
    # WEP 网络的身份验证可能是 “开放/Open” 而加密方式为 WEP，此时以加密方式为准
    if "wep" in compact or cipher_text.lower() == "wep":
        return "WEP"
    if not compact or compact in ("none", "open", "off", "无", "未加密", "开放"):
        return "Open"
    if "owe" in compact:
        return "OWE (Enhanced Open)"
    has_8021x = "8021x" in compact or "enterprise" in compact or "eap" in compact
    has_sae = "sae" in compact
    has_wpa3 = "wpa3" in compact or has_sae
    has_wpa2 = "wpa2" in compact
    has_psk = "psk" in compact or "personal" in compact

    if has_wpa3:
        if has_8021x:
            return "WPA3-Enterprise"
        if has_wpa2:
            return "WPA2/WPA3 (过渡)"
        return "WPA3-SAE" if has_sae else "WPA3-Personal"
    if has_wpa2:
        if has_8021x:
            return "WPA2-Enterprise"
        if "wpa1" in compact:
            return "WPA1/WPA2 (过渡)"
        return "WPA2-Personal"
    if compact.startswith("wpa") or "wpa1" in compact:
        return "WPA-Enterprise" if has_8021x else "WPA-Personal"
    if has_psk:
        return "WPA2-Personal"
    return text or "Unknown"


def _run(cmd: list[str], timeout: int = 45) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


def _mark_saved(networks: list[ScanNetwork], saved_ssids: set[str] | None) -> None:
    if not saved_ssids:
        return
    keys = {s.strip().casefold() for s in saved_ssids if s.strip()}
    for net in networks:
        if net.ssid:
            net.saved = net.ssid.casefold() in keys


# --------------------------------------------------------------------------- Windows: netsh

_NETSH_SSID = re.compile(r"^\s*SSID\s+\d+\s*:\s*(.*)$", re.IGNORECASE)
_NETSH_BSSID = re.compile(
    r"^\s*BSSID\s+\d+\s*:\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", re.IGNORECASE
)
_NETSH_LABELS = {
    "authentication": "auth",
    "身份验证": "auth",
    "encryption": "cipher",
    "加密": "cipher",
    "signal": "signal",
    "信号": "signal",
    "channel": "channel",
    "信道": "channel",
    "频道": "channel",
    "band": "band",
    "波段": "band",
    "频段": "band",
    "radio type": "radio",
    "无线电类型": "radio",
}


def _bss_band(bss: dict) -> str:
    """优先使用系统给出的频段，否则按信道号推断。"""
    return bss.get("band") or band_of_channel(bss["channel"])


def _aggregate_block(block: dict, source: str) -> list[ScanNetwork]:
    """把一个 SSID 块内的多个 BSSID 按频段聚合成扫描结果。"""
    ssid = block.get("ssid") or ""
    security = normalize_security(block.get("auth") or "", block.get("cipher"))
    cipher = block.get("cipher")
    bsss = block.get("bsss") or []

    if not ssid:  # 隐藏 SSID：每个 BSSID 单独一行
        return [
            ScanNetwork(
                ssid="",
                bssid=b["bssid"],
                signal=b["signal"],
                channel=b["channel"],
                band=_bss_band(b),
                security=security,
                cipher=cipher,
                bssid_count=1,
                source=source,
            )
            for b in bsss
        ]

    groups: dict[str, list[dict]] = {}
    for b in bsss:
        groups.setdefault(_bss_band(b), []).append(b)
    out = []
    for band, items in groups.items():
        best = max(items, key=lambda b: b["signal"])
        out.append(
            ScanNetwork(
                ssid=ssid,
                bssid=best["bssid"],
                signal=best["signal"],
                channel=best["channel"],
                band=band,
                security=security,
                cipher=cipher,
                bssid_count=len(items),
                source=source,
            )
        )
    out.sort(key=lambda n: -n.signal)
    return out


def parse_netsh_networks(output: str) -> list[ScanNetwork]:
    """解析 ``netsh wlan show networks mode=bssid``（兼容英文与中文标签）。"""
    networks: list[ScanNetwork] = []
    block: dict | None = None

    def flush() -> None:
        nonlocal block
        if block:
            networks.extend(_aggregate_block(block, "netsh"))
        block = None

    for raw in output.splitlines():
        sm = _NETSH_SSID.match(raw)
        if sm:
            flush()
            block = {
                "ssid": sm.group(1).strip().strip("\"“”'‘’"),
                "auth": None,
                "cipher": None,
                "bsss": [],
            }
            continue
        bm = _NETSH_BSSID.match(raw)
        if bm and block is not None:
            block["bsss"].append(
                {"bssid": bm.group(1).lower(), "signal": 0, "channel": None, "band": "", "radio": ""}
            )
            continue
        if block is None or ":" not in raw:
            continue
        label, value = raw.split(":", 1)
        key = _NETSH_LABELS.get(label.strip().lower())
        if not key:
            continue
        value = value.strip()
        if key in ("auth", "cipher"):
            if value and value.lower() not in ("none", "") and value != "无":
                block[key] = value
        elif key == "signal":
            m = re.search(r"(\d+)", value)
            if m and block["bsss"]:
                block["bsss"][-1]["signal"] = max(0, min(100, int(m.group(1))))
        elif key == "channel":
            m = re.search(r"(\d+)", value)
            if m and block["bsss"]:
                block["bsss"][-1]["channel"] = int(m.group(1))
        elif key == "band":
            if value and block["bsss"]:
                block["bsss"][-1]["band"] = value
    flush()
    return networks


# --------------------------------------------------------------------------- Linux: nmcli

NMCLI_FIELDS = "SSID,BSSID,SIGNAL,CHAN,FREQ,SECURITY"


def _nmcli_unescape(value: str) -> str:
    return value.replace("\\:", ":").replace("\\\\", "\\")


def parse_nmcli_scan(output: str) -> list[ScanNetwork]:
    """解析 ``nmcli -t -f ... device wifi list`` 的 TSV 输出。"""
    networks: list[ScanNetwork] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = re.split(r"(?<!\\):", line)
        if len(parts) < 6:
            continue
        ssid = _nmcli_unescape(parts[0])
        bssid = _nmcli_unescape(parts[1]).lower()
        try:
            signal = max(0, min(100, int(parts[2])))
        except ValueError:
            signal = 0
        try:
            channel = int(parts[3])
        except ValueError:
            channel = None
        freq = None
        m = re.search(r"(\d+)", parts[4])
        if m:
            freq = int(m.group(1))
        networks.append(
            ScanNetwork(
                ssid=ssid,
                bssid=bssid,
                signal=signal,
                channel=channel,
                band=band_of_channel(channel, freq),
                security=normalize_security(_nmcli_unescape(parts[5])),
                bssid_count=1,
                source="nmcli",
            )
        )
    networks.sort(key=lambda n: -n.signal)
    return networks


# --------------------------------------------------------------------------- macOS: airport / system_profiler

_AIRPORT_ROW = re.compile(
    r"^\s*(.*?)\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+(-?\d+)\s+(\d+)(\S*)\s+(\S+)\s+(\S+)\s*(.*)$"
)


def _airport_cipher(security: str) -> str | None:
    """从 ``WPA2(PSK/AES/AES)`` 中提取单播加密方式。"""
    m = re.search(r"\(([^)]+)\)", security)
    if not m:
        return None
    parts = [p.strip() for p in m.group(1).split("/")]
    if len(parts) >= 2:
        return {"AES": "CCMP", "TKIP": "TKIP", "GCMP": "GCMP"}.get(parts[1].upper(), parts[1])
    return None


def parse_airport_scan(output: str) -> list[ScanNetwork]:
    """解析 ``airport -s`` 输出（首行为表头，跳过）。"""
    networks: list[ScanNetwork] = []
    for line in output.splitlines()[1:]:
        m = _AIRPORT_ROW.match(line)
        if not m:
            continue
        security_raw = m.group(8).strip()
        networks.append(
            ScanNetwork(
                ssid=m.group(1).strip(),
                bssid=m.group(2).lower(),
                signal=rssi_to_percent(int(m.group(3))),
                channel=int(m.group(4)),
                band=band_of_channel(int(m.group(4))),
                security=normalize_security(security_raw),
                cipher=_airport_cipher(security_raw),
                bssid_count=1,
                source="airport",
            )
        )
    networks.sort(key=lambda n: -n.signal)
    return networks


_PROFILER_ATTRS = {"BSSID", "PHY Mode", "Channel", "Security", "Signal", "Network Type"}


def _profiler_block_to_net(block: dict) -> ScanNetwork:
    return ScanNetwork(
        ssid=block.get("ssid", ""),
        bssid=(block.get("bssid") or "").lower(),
        signal=block.get("signal", 0),
        channel=block.get("channel"),
        band=band_of_channel(block.get("channel"), block.get("freq")),
        security=normalize_security(block.get("security", "")),
        bssid_count=1,
        source="system_profiler",
    )


def parse_system_profiler_text(output: str) -> list[ScanNetwork]:
    """解析 ``system_profiler SPAirPortDataType`` 文本中的“其他本地 Wi-Fi 网络”。"""
    networks: list[ScanNetwork] = []
    in_section = False
    current: dict | None = None

    def flush() -> None:
        nonlocal current
        if current is not None:
            networks.append(_profiler_block_to_net(current))
        current = None

    for line in output.splitlines():
        if not line.strip():
            continue
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if "Other Local Wi-Fi Networks" in line:  # 小节标题（按内容识别，不受缩进影响）
            flush()
            in_section = True
            continue
        if not in_section:
            continue
        if indent <= 6:  # 其他小节标题，离开网络列表
            flush()
            in_section = False
            continue
        if ":" in line:
            label, value = line.split(":", 1)
            label = label.strip()
            if current is not None and label in _PROFILER_ATTRS:
                value = value.strip()
                if label == "Channel":
                    m = re.search(r"(\d+)", value)
                    fm = re.search(r"([\d.]+)\s*GHz", value)
                    if m:
                        current["channel"] = int(m.group(1))
                    if fm:
                        current["freq"] = int(float(fm.group(1)) * 1000)
                elif label == "Signal":
                    m = re.search(r"(-?\d+)", value)
                    if m:
                        v = int(m.group(1))
                        current["signal"] = v if v > 0 else rssi_to_percent(v)
                else:
                    current[label.lower().replace(" ", "_")] = value
                continue
        if stripped.endswith(":") and stripped.count(":") == 1 and indent >= 8:
            flush()
            current = {"ssid": stripped[:-1]}
    flush()
    return networks


def parse_system_profiler_json(text: str) -> list[ScanNetwork]:
    """解析 ``system_profiler SPAirPortDataType -json``（新 macOS）。"""
    data = _json.loads(text)
    networks: list[ScanNetwork] = []
    for iface in data.get("SPAirPortDataType", []):
        entries = iface.get("spairport_airport_other_local_wireless_networks") or []
        for entry in entries:
            channel_raw = str(entry.get("spairport_airport_network_channel", "") or "")
            cm = re.search(r"(\d+)", channel_raw)
            fm = re.search(r"([\d.]+)\s*GHz", channel_raw)
            channel = int(cm.group(1)) if cm else None
            freq = int(float(fm.group(1)) * 1000) if fm else None
            signal_raw = str(entry.get("spairport_airport_network_signal", "0") or "0")
            sm = re.search(r"(\d+)", signal_raw)
            signal = max(0, min(100, int(sm.group(1)))) if sm else 0
            networks.append(
                ScanNetwork(
                    ssid=entry.get("_name", "") or "",
                    bssid=(entry.get("spairport_airport_network_bssid") or "").lower(),
                    signal=signal,
                    channel=channel,
                    band=band_of_channel(channel, freq),
                    security=normalize_security(entry.get("spairport_airport_network_security", "")),
                    bssid_count=1,
                    source="system_profiler",
                )
            )
    networks.sort(key=lambda n: -n.signal)
    return networks


# --------------------------------------------------------------------------- 平台入口


def _scan_linux() -> tuple[list[ScanNetwork], str]:
    if shutil.which("nmcli"):
        code, out = _run(
            ["nmcli", "--terse", "--fields", NMCLI_FIELDS, "device", "wifi", "list"]
        )
        if code == 0:
            nets = parse_nmcli_scan(out)
            if nets:
                return nets, "nmcli device wifi list"
    return [], "nmcli"


def _scan_macos() -> tuple[list[ScanNetwork], str]:
    if Path(AIRPORT_BIN).exists():
        code, out = _run([AIRPORT_BIN, "-s"], timeout=30)
        if code == 0:
            nets = parse_airport_scan(out)
            if nets:
                return nets, "airport -s"
    code, out = _run(["system_profiler", "SPAirPortDataType", "-json"], timeout=90)
    if code == 0 and out:
        try:
            nets = parse_system_profiler_json(out)
            if nets:
                return nets, "system_profiler (JSON)"
        except (ValueError, KeyError, TypeError):
            pass
    code, out = _run(["system_profiler", "SPAirPortDataType"], timeout=90)
    if code == 0:
        nets = parse_system_profiler_text(out)
        if nets:
            return nets, "system_profiler"
    return [], "system_profiler"


def scan_networks(saved_ssids: set[str] | None = None) -> tuple[list[ScanNetwork], str]:
    """扫描周围可见的无线网络，返回 (网络列表, 数据源描述)。只读，不连接任何网络。"""
    if sys.platform == "win32":
        code, out = run_netsh(["wlan", "show", "networks", "mode=bssid"], timeout=30)
        if code == 0:
            nets = parse_netsh_networks(out)
            _mark_saved(nets, saved_ssids)
            return nets, "netsh wlan show networks"
        return [], "netsh"
    if sys.platform == "darwin":
        nets, source = _scan_macos()
        _mark_saved(nets, saved_ssids)
        return nets, source
    nets, source = _scan_linux()
    _mark_saved(nets, saved_ssids)
    return nets, source


# --------------------------------------------------------------------------- 环境评估


@dataclass(slots=True)
class ScanSummary:
    """周围无线环境的统计与观察。"""

    total: int
    open_count: int = 0
    wep_count: int = 0
    legacy_count: int = 0
    wpa3_count: int = 0
    saved_count: int = 0
    bands: dict[str, int] = field(default_factory=dict)
    overlap_24: dict[int, int] = field(default_factory=dict)  # 信道 1/6/11 → 重叠网络数
    findings: list[Finding] = field(default_factory=list)


def scan_environment(
    networks: list[ScanNetwork], saved_networks: list[WifiNetwork] | None = None
) -> ScanSummary:
    """对扫描结果做环境安全评估（信道拥挤、开放网络、疑似同名仿冒热点等）。"""
    saved_networks = saved_networks or []
    bands: dict[str, int] = {}
    for net in networks:
        if net.band:
            bands[net.band] = bands.get(net.band, 0) + 1

    channels_24 = [n.channel for n in networks if n.band == "2.4 GHz" and n.channel]
    overlap = {c: sum(1 for ch in channels_24 if abs(ch - c) <= 4) for c in (1, 6, 11)}

    summary = ScanSummary(
        total=len(networks),
        open_count=sum(1 for n in networks if n.is_open),
        wep_count=sum(1 for n in networks if n.is_wep),
        legacy_count=sum(1 for n in networks if n.is_legacy),
        wpa3_count=sum(1 for n in networks if n.is_wpa3),
        saved_count=sum(1 for n in networks if n.saved),
        bands=bands,
        overlap_24=overlap,
    )

    findings: list[Finding] = []

    # 同名仿冒热点：附近出现与你已保存“加密网络”同名的开放网络
    saved_secured = {n.ssid.casefold(): n for n in saved_networks if n.ssid and not n.is_open}
    seen_spoof: set[str] = set()
    for net in networks:
        if net.is_open and net.ssid and net.ssid.casefold() in saved_secured and net.ssid.casefold() not in seen_spoof:
            seen_spoof.add(net.ssid.casefold())
            findings.append(
                Finding(
                    code="scan_spoof",
                    severity="high",
                    ssid=net.ssid,
                    title="疑似同名仿冒开放网络",
                    detail=f"附近的开放网络“{net.ssid}”与你已保存的加密网络同名，"
                    "可能是仿冒热点（evil twin）。连接前请确认来源，避免在其中有敏感操作。",
                )
            )

    if summary.open_count:
        findings.append(
            Finding(
                code="scan_open",
                severity="info",
                title=f"附近有 {summary.open_count} 个开放网络",
                detail="开放网络的流量可能被监听或劫持，连接时避免登录账号、支付等敏感操作。",
            )
        )
    if summary.wep_count:
        findings.append(
            Finding(
                code="scan_wep",
                severity="low",
                title=f"附近有 {summary.wep_count} 个 WEP 网络",
                detail="WEP 加密数分钟内即可被破解（这是他人的网络配置问题），不要连接此类网络。",
            )
        )
    if summary.legacy_count:
        findings.append(
            Finding(
                code="scan_legacy",
                severity="low",
                title=f"附近有 {summary.legacy_count} 个老式加密网络（TKIP / WPA1）",
                detail="老式加密已不安全（他人的网络配置问题），仅作环境观察。",
            )
        )
    if channels_24 and max(overlap.values()) >= 8:
        best = min(overlap, key=lambda c: overlap[c])
        worst = max(overlap.values())
        findings.append(
            Finding(
                code="scan_congestion",
                severity="low",
                title=f"2.4GHz 频段拥挤（单个信道最多 {worst} 个网络重叠）",
                detail=f"推荐信道 1/6/11 当前重叠网络数为 {overlap}，信道 {best} 相对空闲；"
                "自己的路由器可考虑切换到 5GHz。",
            )
        )
    summary.findings = findings
    return summary
