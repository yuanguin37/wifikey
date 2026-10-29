"""平台数据源基类。"""

from __future__ import annotations

from wifikey.models import WifiNetwork


class Provider:
    """读取本机已保存 WiFi 配置的抽象接口。"""

    name = "base"
    display_name = "Unknown"
    note = ""

    def available(self) -> tuple[bool, str]:
        """返回 (是否可用, 说明)。"""
        return True, ""

    def list_networks(self, include_passwords: bool = True) -> list[WifiNetwork]:
        raise NotImplementedError

    def current_ssid(self) -> str | None:
        """当前已连接网络名，未知时返回 None。"""
        return None
