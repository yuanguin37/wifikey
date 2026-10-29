"""统一的数据模型。"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any


MASK = "••••••••"


@dataclass(slots=True)
class WifiNetwork:
    """一个已保存的无线网络配置。"""

    ssid: str
    password: str | None = None
    # 形如 WPA2-Personal / WPA3-SAE / WPA-Enterprise / WEP / Open / Unknown
    security: str = "Unknown"
    cipher: str | None = None
    auth: str | None = None
    connection_mode: str | None = None  # auto / manual
    hidden: bool = False
    interface: str | None = None
    source: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def has_password(self) -> bool:
        return bool(self.password)

    @property
    def is_open(self) -> bool:
        text = f"{self.security} {self.auth or ''}".lower()
        return any(k in text for k in ("open", "none", "开放", "无身份验证"))

    @property
    def is_enterprise(self) -> bool:
        text = f"{self.security} {self.auth or ''}".lower()
        return any(k in text for k in ("enterprise", "802.1x", "eap", "企业"))

    @property
    def is_wep(self) -> bool:
        return "wep" in f"{self.security} {self.auth or ''}".lower()

    @property
    def uses_tkip(self) -> bool:
        return "tkip" in (self.cipher or "").lower()

    @property
    def is_wpa1_only(self) -> bool:
        text = self.security.lower().replace("-", "")
        return "wpa" in text and "wpa2" not in text and "wpa3" not in text and not self.is_wep

    def to_dict(self, reveal: bool = True) -> dict[str, Any]:
        data = asdict(self)
        if not reveal and data["password"]:
            data["password"] = MASK
            data["password_masked"] = True
        return data


@dataclass(slots=True)
class Finding:
    """审计发现的一条风险项。"""

    code: str
    severity: str  # critical / high / medium / low / info
    title: str
    detail: str = ""
    ssid: str = ""


@dataclass(slots=True)
class PasswordAssessment:
    score: int  # 0-100
    grade: str  # 极弱 / 弱 / 中 / 强
    issues: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AuditReport:
    networks: list[WifiNetwork]
    findings: list[Finding]
    stats: dict[str, Any]
    score: int  # 0-100 整体健康度


@dataclass(slots=True)
class ScanNetwork:
    """周围一个可见的无线网络（被动扫描结果，只包含广播信息，不涉及密码）。"""

    ssid: str = ""  # 空串表示隐藏 SSID 的网络
    bssid: str = ""
    signal: int = 0  # 信号强度 0-100（百分比）
    channel: int | None = None
    band: str = ""  # "2.4 GHz" / "5 GHz" / "6 GHz" / ""
    security: str = "Unknown"  # 归一化后的安全类型
    cipher: str | None = None  # CCMP / TKIP / GCMP / WEP
    saved: bool = False  # 本机是否保存过该 SSID 的配置
    bssid_count: int = 1  # 同名同频段可见 AP（BSSID）数量
    source: str = ""  # netsh / nmcli / airport / system_profiler

    @property
    def display_ssid(self) -> str:
        return self.ssid or "（隐藏网络）"

    @property
    def is_open(self) -> bool:
        return self.security.strip().lower() in ("", "open")

    @property
    def is_wep(self) -> bool:
        return "wep" in self.security.lower()

    @property
    def uses_tkip(self) -> bool:
        return "tkip" in (self.cipher or "").lower()

    @property
    def is_wpa3(self) -> bool:
        low = self.security.lower()
        return "wpa3" in low or "sae" in low

    def _compact_security(self) -> str:
        return re.sub(r"[\s()\-/]+", "", self.security.lower())

    @property
    def is_wpa1_only(self) -> bool:
        compact = self._compact_security()
        if "wep" in compact or "wpa2" in compact or "wpa3" in compact:
            return False
        return compact.startswith("wpa")

    @property
    def is_legacy(self) -> bool:
        """WEP / TKIP / WPA1（含 WPA1 过渡模式）等落后加密。"""
        compact = self._compact_security()
        return self.is_wep or self.uses_tkip or "wpa1" in compact or self.is_wpa1_only
