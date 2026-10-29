"""终端渲染：网络列表、详情、审计报告。"""

from __future__ import annotations

from wifikey.audit import assess_password
from wifikey.models import AuditReport, Finding, ScanNetwork, WifiNetwork
from wifikey.textutil import (
    SEVERITY_COLOR,
    SEVERITY_LABEL,
    c,
    grade_color,
    render_table,
    strength_bar,
    truncate,
)


def risk_of(net: WifiNetwork) -> tuple[str, str] | None:
    """返回 (等级, 简短说明)，按严重程度取最高的一项。"""
    candidates: list[tuple[str, str]] = []
    if net.is_open:
        candidates.append(("critical", "开放"))
    if net.is_wep:
        candidates.append(("critical", "WEP"))
    if net.uses_tkip:
        candidates.append(("high", "TKIP"))
    if net.is_wpa1_only:
        candidates.append(("high", "WPA"))
    if net.password:
        score = assess_password(net.password).score
        if score < 35:
            candidates.append(("high", "极弱密码"))
        elif score < 55:
            candidates.append(("medium", "弱密码"))
    if net.hidden:
        candidates.append(("low", "隐藏"))
    if not candidates:
        return None
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    candidates.sort(key=lambda item: order[item[0]])
    return candidates[0]


def _risk_cell(net: WifiNetwork) -> str:
    risk = risk_of(net)
    if not risk:
        return c("正常", "green")
    severity, label = risk
    return c(f"{SEVERITY_LABEL[severity]}/{label}", SEVERITY_COLOR[severity])


def render_network_table(networks: list[WifiNetwork], reveal: bool = True, current: str | None = None) -> str:
    rows = []
    for index, net in enumerate(networks, start=1):
        ssid = truncate(net.ssid, 26)
        if current and net.ssid == current:
            ssid = f"★ {ssid}"
        if net.password:
            pwd = net.password if reveal else "••••••••"
        elif net.is_open:
            pwd = "（开放网络）"
        else:
            pwd = c("（未读取）", "gray")
        assessment = assess_password(net.password)
        if net.password:
            strength = c(
                f"{strength_bar(assessment.score, 6)} {assessment.grade}",
                grade_color(assessment.grade),
            )
        else:
            strength = c("—", "gray")
        rows.append(
            [
                str(index),
                ssid,
                net.security,
                net.cipher or "—",
                pwd,
                strength,
                _risk_cell(net),
            ]
        )
    table = render_table(
        ["#", "SSID", "安全类型", "加密", "密码", "强度", "风险"],
        rows,
        aligns=["right", "left", "left", "left", "left", "left", "left"],
        max_widths=[4, 26, 20, 10, 40, 18, 20],
    )
    return table


def render_detail(net: WifiNetwork, findings: list[Finding], reveal: bool = True) -> str:
    assessment = assess_password(net.password)
    password_text = "（无 / 未读取）"
    if net.password:
        password_text = net.password if reveal else "••••••••"
    elif net.is_open:
        password_text = "（开放网络，无需密码）"

    lines = [
        c(f"● {net.ssid}", "bold"),
        f"  安全类型   {net.security}"
        + (f"  ·  {net.cipher}" if net.cipher else ""),
        f"  密码       {password_text}",
    ]
    if net.password:
        lines.append(
            f"  密码强度   {c(f'{assessment.grade} ({assessment.score}/100)', grade_color(assessment.grade))}  "
            f"{strength_bar(assessment.score, 20)}"
        )
        if assessment.issues:
            lines.append(f"            {c('；'.join(assessment.issues), 'gray')}")
    lines += [
        f"  连接模式   {'自动连接' if net.connection_mode == 'auto' else '手动连接' if net.connection_mode else '未知'}",
        f"  隐藏 SSID  {'是' if net.hidden else '否'}",
        f"  数据来源   {net.source}" + (f"  ({net.extra.get('path')})" if net.extra.get("path") else ""),
    ]
    if findings:
        lines.append("")
        lines.append("  关联风险:")
        for finding in findings:
            color = SEVERITY_COLOR.get(finding.severity, "gray")
            lines.append(
                f"    {c('[' + SEVERITY_LABEL.get(finding.severity, finding.severity) + ']', color)} "
                f"{finding.title}" + (f" — {c(finding.detail, 'gray')}" if finding.detail else "")
            )
    else:
        lines += ["", "  " + c("未发现与该网络相关的风险项。", "green")]
    return "\n".join(lines)


def render_audit(report: AuditReport) -> str:
    stats = report.stats
    color = "green" if report.score >= 80 else "yellow" if report.score >= 55 else "red"
    lines = [
        c("WiFiKey 安全审计", "bold"),
        "",
        f"  整体健康度   {c(str(report.score) + '/100', color)}  {strength_bar(report.score, 24)}",
        f"  已保存网络   {stats['total']} 个   可读取密码 {stats['with_password']} 个",
        f"  弱密码       {stats['weak']} 个   开放网络 {stats['open']} 个   WEP {stats['wep']} 个",
        f"  隐藏 SSID    {stats['hidden']} 个   企业网络 {stats['enterprise']} 个",
    ]
    by_sev = stats["by_severity"]
    lines.append(
        "  风险分布     "
        + "  ".join(
            f"{c(SEVERITY_LABEL[sev] + ' ' + str(by_sev.get(sev, 0)), SEVERITY_COLOR[sev])}"
            for sev in ("critical", "high", "medium", "low", "info")
        )
    )
    if stats.get("reused_groups"):
        lines.append("  复用密码组   " + "；".join(" ↔ ".join(group) for group in stats["reused_groups"]))

    lines.append("")
    if report.findings:
        lines.append(c("风险明细", "bold"))
        for finding in report.findings:
            color = SEVERITY_COLOR.get(finding.severity, "gray")
            title = c(f"[{SEVERITY_LABEL.get(finding.severity, finding.severity)}]", color)
            lines.append(f"  {title} {finding.ssid}  {finding.title}")
            if finding.detail:
                lines.append(f"        {c(finding.detail, 'gray')}")
    else:
        lines.append(c("  未发现明显风险。", "green"))
    return "\n".join(lines)


# --------------------------------------------------------------------------- 周围网络扫描


def scan_risk_of(net: ScanNetwork) -> tuple[str, str] | None:
    """扫描网络的风险标签：面向“是否建议连接/环境观察”。"""
    if net.is_wep:
        return ("low", "WEP")
    if net.is_open:
        return ("medium", "开放")
    if net.is_legacy:
        return ("low", "老式加密")
    return None


def render_scan_table(networks: list[ScanNetwork], current_ssid: str | None = None) -> str:
    rows = []
    for index, net in enumerate(networks, start=1):
        ssid = truncate(net.display_ssid, 26)
        if current_ssid and net.ssid and net.ssid == current_ssid:
            ssid = f"★ {ssid}"
        signal = f"{strength_bar(net.signal, 5)} {net.signal}%"
        saved = c("★ 已保存", "green") if net.saved else ""
        risk = scan_risk_of(net)
        risk_text = (
            c(f"{SEVERITY_LABEL[risk[0]]}·{risk[1]}", SEVERITY_COLOR[risk[0]]) if risk else c("—", "gray")
        )
        rows.append(
            [
                str(index),
                ssid,
                signal,
                str(net.channel if net.channel is not None else "—"),
                net.band or "—",
                net.security,
                str(net.bssid_count),
                saved,
                risk_text,
            ]
        )
    return render_table(
        ["#", "SSID", "信号", "信道", "频段", "安全类型", "AP", "已保存", "风险"],
        rows,
        aligns=["right", "left", "left", "right", "left", "left", "right", "left", "left"],
        max_widths=[4, 26, 14, 6, 8, 22, 4, 10, 14],
    )


def render_scan_summary(summary, source: str = "", scanned_at: str = "") -> str:
    """渲染周围网络环境摘要（summary 为 scanner.ScanSummary）。"""
    bands_text = " · ".join(f"{k} {v}" for k, v in sorted(summary.bands.items()))
    lines = [
        c("周围无线环境评估", "bold"),
        "",
        f"  数据来源   {source or '—'}" + (f"   ·   扫描于 {scanned_at}" if scanned_at else ""),
        f"  可见网络   {summary.total} 个" + (f"（{bands_text}）" if bands_text else ""),
        "  开放 {} · WEP {} · 老式加密 {} · WPA3 {} · 本机已保存 {}".format(
            summary.open_count, summary.wep_count, summary.legacy_count, summary.wpa3_count, summary.saved_count
        ),
    ]
    if summary.findings:
        lines.append("")
        lines.append(c("环境观察", "bold"))
        for finding in summary.findings:
            color = SEVERITY_COLOR.get(finding.severity, "gray")
            title = c(f"[{SEVERITY_LABEL.get(finding.severity, finding.severity)}]", color)
            head = f"  {title} {(finding.ssid + ' — ') if finding.ssid else ''}{finding.title}"
            lines.append(head)
            if finding.detail:
                lines.append(f"        {c(finding.detail, 'gray')}")
    lines.append("")
    lines.append(
        c("  说明: 扫描只列出网卡可见的网络（同系统 WiFi 列表），无法也不尝试获取未保存网络的密码。", "gray")
    )
    return "\n".join(lines)
