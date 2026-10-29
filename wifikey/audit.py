"""安全审计：密码强度评估与网络风险检测。

只做静态分析，不发起任何网络探测或连接行为。
"""

from __future__ import annotations

import math
import re
from collections import defaultdict

from wifikey.models import AuditReport, Finding, PasswordAssessment, WifiNetwork

COMMON_PASSWORDS = {
    "12345678", "123456789", "1234567890", "11111111", "00000000", "88888888",
    "password", "password1", "passw0rd", "qwerty123", "qwertyuiop", "abc12345",
    "1q2w3e4r", "1qaz2wsx", "admin123", "root1234", "wifi1234", "wlan1234",
    "iloveyou", "letmein1", "welcome1", "monkey123", "dragon123", "sunshine",
    "woaini1314", "5201314520", "a1234567", "aa123456", "abcd1234", "test1234",
    "guest123", "changeme", "default1", "66668888", "147258369", "987654321",
}

_SEQUENCES = (
    "0123456789", "9876543210", "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba", "qwertyuiop", "asdfghjkl", "zxcvbnm",
)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# 单个网络的风险扣分（0-100 分制），按风险类型计
_NETWORK_PENALTY = {
    "open_network": 45,
    "wep_encryption": 50,
    "tkip_cipher": 20,
    "wpa1_only": 15,
    "weak_password": 30,
    "reused_password": 12,
    "hidden_ssid": 5,
    "enterprise_network": 0,
    "no_password": 0,
}


def _has_sequence(password: str) -> bool:
    lowered = password.lower()
    for seq in _SEQUENCES:
        for i in range(len(seq) - 3):
            if seq[i : i + 4] in lowered or seq[i : i + 4][::-1] in lowered:
                return True
    return False


def assess_password(password: str | None) -> PasswordAssessment:
    """评估单个密码的强度，返回 0-100 分。"""
    if not password:
        return PasswordAssessment(0, "无密码", ["没有可用密码"])

    issues: list[str] = []
    length = len(password)
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33
    if re.search(r"[^\x00-\x7f]", password):
        pool += 60

    bits = length * math.log2(pool) if pool else 0
    score = min(bits, 110) / 110 * 65 + min(length, 20) * 1.5

    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        issues.append("常见弱口令")
        score = min(score, 15)
    else:
        for word in ("password", "admin", "qwerty", "wifi", "wlan", "abc123", "123456", "888888", "woaini"):
            if word in lowered:
                issues.append(f"包含常见片段 “{word}”")
                score -= 18
                break

    if password.isdigit():
        issues.append("纯数字密码")
        score -= 15
    if len(set(password)) == 1:
        issues.append("全部为相同字符")
        score = min(score, 8)
    if _has_sequence(password):
        issues.append("包含键盘/字母连续序列")
        score -= 12
    if length < 8:
        issues.append("长度不足 8 位")
        score -= 20
    elif length < 10:
        issues.append("长度偏短（少于 10 位）")
        score -= 6
    if length >= 8 and not re.search(r"[^a-zA-Z]", password) and password.isalpha():
        issues.append("仅由字母组成")
        score -= 8

    score = int(max(0, min(100, round(score))))
    if score >= 80:
        grade = "强"
    elif score >= 55:
        grade = "中"
    elif score >= 35:
        grade = "弱"
    else:
        grade = "极弱"
    return PasswordAssessment(score, grade, issues)


def audit_networks(networks: list[WifiNetwork]) -> AuditReport:
    """对整份网络清单做安全审计。"""
    findings: list[Finding] = []
    assessments: dict[str, PasswordAssessment] = {}

    # 密码复用检测
    reuse: dict[str, list[str]] = defaultdict(list)
    for net in networks:
        if net.password and not net.is_open:
            reuse[net.password].append(net.ssid)
    reused_groups = [sorted(v) for v in reuse.values() if len({s.casefold() for s in v}) > 1]

    for net in networks:
        assessment = assess_password(net.password)
        assessments[net.ssid] = assessment

        if net.is_open:
            findings.append(
                Finding("open_network", "critical", "开放网络无加密", "任何人都可接入，建议改为 WPA2/WPA3。", net.ssid)
            )
        if net.is_wep:
            findings.append(
                Finding("wep_encryption", "critical", "使用已被攻破的 WEP 加密", "WEP 可在数分钟内被破解。", net.ssid)
            )
        if net.uses_tkip:
            findings.append(
                Finding("tkip_cipher", "high", "使用 TKIP 加密", "TKIP 已被淘汰，建议使用 CCMP/GCMP。", net.ssid)
            )
        if net.is_wpa1_only:
            findings.append(
                Finding("wpa1_only", "high", "仅使用 WPA/WPA2 早期模式", "建议启用 WPA2-AES 或 WPA3。", net.ssid)
            )
        if net.is_enterprise:
            findings.append(
                Finding("enterprise_network", "info", "企业级 802.1X 网络", "不保存共享密码，密码由认证服务器下发。", net.ssid)
            )
        elif not net.password and not net.is_open:
            findings.append(
                Finding("no_password", "info", "未读取到密码", "可能是权限不足、密钥受保护或密码由系统代理保存。", net.ssid)
            )

        if net.password and assessment.score < 55:
            severity = "high" if assessment.score < 35 else "medium"
            findings.append(
                Finding(
                    "weak_password",
                    severity,
                    f"密码强度不足（{assessment.score} 分 / {assessment.grade}）",
                    "；".join(assessment.issues) or "建议更换为更长的随机密码。",
                    net.ssid,
                )
            )

        if net.hidden:
            findings.append(
                Finding("hidden_ssid", "low", "隐藏 SSID", "隐藏 SSID 不能提升安全性，只是增加连接成本。", net.ssid)
            )

        if net.password and any(net.ssid in group for group in reused_groups):
            others = next((g for g in reused_groups if net.ssid in g), [])
            rest = "、".join(s for s in others if s != net.ssid)
            findings.append(
                Finding("reused_password", "medium", "密码与其他网络重复", f"与 {rest} 使用相同密码，一处泄露即全部失效。", net.ssid)
            )

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.ssid.casefold()))

    by_severity: dict[str, int] = {k: 0 for k in _SEVERITY_ORDER}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

    scored = [assessments[n.ssid] for n in networks if n.password]
    avg_score = round(sum(a.score for a in scored) / len(scored)) if scored else 0

    # 整体评分 = 各网络安全得分的平均值（每个网络起始 100 分，按风险扣分）
    health_by_ssid: dict[str, int] = {n.ssid: 100 for n in networks}
    for finding in findings:
        if finding.ssid in health_by_ssid:
            health_by_ssid[finding.ssid] -= _NETWORK_PENALTY.get(finding.code, 0)
    score = round(sum(max(0, v) for v in health_by_ssid.values()) / len(health_by_ssid)) if health_by_ssid else 100
    score = int(max(0, min(100, score)))

    stats = {
        "total": len(networks),
        "with_password": sum(1 for n in networks if n.has_password),
        "open": sum(1 for n in networks if n.is_open),
        "wep": sum(1 for n in networks if n.is_wep),
        "legacy": sum(1 for n in networks if n.is_wep or n.uses_tkip or n.is_wpa1_only),
        "weak": sum(1 for n in networks if n.password and assessments[n.ssid].score < 55),
        "hidden": sum(1 for n in networks if n.hidden),
        "enterprise": sum(1 for n in networks if n.is_enterprise),
        "reused_groups": reused_groups,
        "by_severity": by_severity,
        "average_password_score": avg_score,
        "assessments": {ssid: {"score": a.score, "grade": a.grade, "issues": a.issues} for ssid, a in assessments.items()},
    }
    return AuditReport(networks=networks, findings=findings, stats=stats, score=score)
