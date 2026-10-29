"""终端 / 文本输出相关的小工具（宽字符对齐、颜色、表格）。"""

from __future__ import annotations

import os
import re
import sys
import unicodedata

_ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "gray": "\033[90m",
}

SEVERITY_COLOR = {
    "critical": "red",
    "high": "yellow",
    "medium": "blue",
    "low": "gray",
    "info": "cyan",
}

SEVERITY_LABEL = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}


def color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR") not in (None, "", "0"):
        return True
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):  # pythonw / GUI 下 stdout 可能为 None
        return False


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """去掉 ANSI 颜色码，供 GUI 等不支持颜色的显示环境使用。"""
    return _ANSI_RE.sub("", str(text))


def c(text: str, style: str | None = None) -> str:
    """给文本加 ANSI 颜色（非 TTY 时原样返回）。"""
    if not style or not color_enabled():
        return text
    return f"{_ANSI.get(style, '')}{text}{_ANSI['reset']}"


def display_width(text: str) -> int:
    """按终端显示宽度计算（中日韩全角字符按 2 列，忽略 ANSI 颜色码）。"""
    text = re.sub(r"\x1b\[[0-9;]*m", "", str(text))
    width = 0
    for ch in str(text):
        if unicodedata.combining(ch):
            continue
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width


def pad(text: str, width: int, align: str = "left") -> str:
    text = str(text)
    gap = max(width - display_width(text), 0)
    if align == "right":
        return " " * gap + text
    if align == "center":
        left = gap // 2
        return " " * left + text + " " * (gap - left)
    return text + " " * gap


def truncate(text: str, width: int) -> str:
    """按显示宽度截断，超出部分用 … 代替。"""
    text = str(text)
    if display_width(text) <= width:
        return text
    out, used = "", 0
    for ch in text:
        w = display_width(ch)
        if used + w > width - 1:
            break
        out += ch
        used += w
    return out + "…"


def render_table(
    headers: list[str],
    rows: list[list[str]],
    aligns: list[str] | None = None,
    max_widths: list[int] | None = None,
) -> str:
    """渲染等宽文本表格（支持中文对齐）。"""
    aligns = aligns or ["left"] * len(headers)
    cols = len(headers)
    normalized: list[list[str]] = []
    for row in rows:
        cells = []
        for i in range(cols):
            value = str(row[i]) if i < len(row) else ""
            if max_widths and i < len(max_widths) and max_widths[i]:
                value = truncate(value, max_widths[i])
            cells.append(value)
        normalized.append(cells)

    widths = [display_width(h) for h in headers]
    for row in normalized:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], display_width(cell))

    def line(char: str = "-") -> str:
        return " + ".join(char * (w + 2) for w in widths)

    out = [line(), " | ".join(f" {pad(h, widths[i])} " for i, h in enumerate(headers)), line("=")]
    for row in normalized:
        out.append(" | ".join(f" {pad(cell, widths[i], aligns[i])} " for i, cell in enumerate(row)))
    out.append(line())
    return "\n".join(out)


def strength_bar(score: int, width: int = 10) -> str:
    filled = max(0, min(width, round(score / 100 * width)))
    return "█" * filled + "░" * (width - filled)


def grade_color(grade: str) -> str:
    if grade == "强":
        return "green"
    if grade == "中":
        return "yellow"
    return "red"
