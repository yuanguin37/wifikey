"""跨平台剪贴板写入（无需额外依赖）。"""

from __future__ import annotations

import ctypes
import shutil
import subprocess
import sys


def _windows_copy(text: str) -> bool:
    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x0002
    kernel32 = ctypes.windll.kernel32
    user32 = ctypes.windll.user32

    if not user32.OpenClipboard(None):
        return False
    try:
        user32.EmptyClipboard()
        data = text.encode("utf-16-le")
        handle = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data) + 2)
        if not handle:
            return False
        ptr = kernel32.GlobalLock(handle)
        try:
            ctypes.memmove(ptr, data, len(data))
            ctypes.memset(ptr + len(data), 0, 2)
        finally:
            kernel32.GlobalUnlock(handle)
        user32.SetClipboardData(CF_UNICODETEXT, handle)
        return True
    finally:
        user32.CloseClipboard()


def copy_to_clipboard(text: str) -> bool:
    """把文本写入系统剪贴板，成功返回 True。"""
    try:
        if sys.platform == "win32":
            return _windows_copy(text)
        if sys.platform == "darwin":
            subprocess.run(["pbcopy"], input=text.encode("utf-8"), check=True)
            return True
        for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]):
            if shutil.which(cmd[0]):
                subprocess.run(cmd, input=text.encode("utf-8"), check=True)
                return True
    except Exception:
        return False
    return False
