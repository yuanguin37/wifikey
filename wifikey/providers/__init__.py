"""平台数据源选择。"""

from __future__ import annotations

import sys

from wifikey.providers.base import Provider


def get_provider(force: str = "auto") -> Provider:
    """按当前操作系统选择数据源；force 可强制指定 windows / linux / macos。"""
    target = force
    if target == "auto":
        if sys.platform == "win32":
            target = "windows"
        elif sys.platform == "darwin":
            target = "macos"
        else:
            target = "linux"

    if target == "windows":
        from wifikey.providers.windows import WindowsProvider

        return WindowsProvider()
    if target == "macos":
        from wifikey.providers.macos import MacOSProvider

        return MacOSProvider()
    if target == "linux":
        from wifikey.providers.linux import LinuxProvider

        return LinuxProvider()
    raise ValueError(f"未知的数据源: {force}")
