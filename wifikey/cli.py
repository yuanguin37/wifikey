"""命令行入口：wifikey [子命令]"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import shutil
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from wifikey import __version__
from wifikey.audit import audit_networks
from wifikey.clipboard import copy_to_clipboard
from wifikey.exporters import (
    render_qr_ascii,
    save_qr_image,
    save_text_file,
    to_csv,
    to_html,
    to_json,
    to_txt,
    wifi_qr_payload,
)
from wifikey.models import WifiNetwork
from wifikey.providers import get_provider
from wifikey.providers.base import Provider
from wifikey.terminal import (
    render_audit,
    render_detail,
    render_network_table,
    render_scan_summary,
    render_scan_table,
)
from wifikey.textutil import c


EXAMPLES = """示例:
  wifikey                         查看全部已保存网络
  wifikey list --has-password     只看能读到密码的网络
  wifikey list --weak --mask      只看弱密码，并隐藏密码
  wifikey show "MyWiFi" --copy    查看详情并复制密码
  wifikey scan                    扫描周围可见的 WiFi（只读，不连接）
  wifikey scan --band 5 --sort signal
  wifikey export -f html -o r.html
  wifikey audit                   安全审计
  wifikey qr "MyWiFi"             生成终端二维码
  wifikey gui                     启动图形界面

说明: 仅读取本机已保存的 WiFi 配置；scan 只列出网卡可见的网络广播信息，
不会破解或连接任何未保存的网络，也无法获取未保存网络的密码。
"""


def _common_flags() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--provider", choices=["auto", "windows", "linux", "macos"], default=argparse.SUPPRESS,
        help="强制指定数据源（默认按系统自动选择）",
    )
    common.add_argument("--mask", action="store_true", default=argparse.SUPPRESS, help="隐藏密码")
    common.add_argument(
        "--no-passwords", action="store_true", default=argparse.SUPPRESS,
        help="完全不读取密码（仅列出网络，适合截图/演示）",
    )
    return common


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wifikey",
        description="WiFiKey · 跨平台已保存 WiFi 密码查看、安全审计与报表工具",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"WiFiKey {__version__}")
    parser.add_argument(
        "--provider", choices=["auto", "windows", "linux", "macos"], default="auto",
        help="强制指定数据源（默认按系统自动选择）",
    )
    parser.add_argument("--mask", action="store_true", help="隐藏密码")
    parser.add_argument("--no-passwords", action="store_true", help="完全不读取密码")

    common = _common_flags()
    sub = parser.add_subparsers(dest="command")

    p_list = sub.add_parser("list", aliases=["ls"], parents=[common], help="列出已保存网络")
    p_list.add_argument("--search", "-s", default="", help="按 SSID / 安全类型搜索")
    p_list.add_argument("--has-password", action="store_true", help="仅显示有密码的网络")
    p_list.add_argument("--weak", action="store_true", help="仅显示弱密码网络")
    p_list.add_argument("--open", action="store_true", help="仅显示开放网络")
    p_list.add_argument("--legacy", action="store_true", help="仅显示 WEP/TKIP/WPA 老式加密")
    p_list.add_argument("--hidden", action="store_true", help="仅显示隐藏 SSID")
    p_list.add_argument("--current", action="store_true", help="仅显示当前已连接网络")
    p_list.add_argument("--sort", choices=["name", "security", "score"], default="name", help="排序方式")
    p_list.add_argument("--format", "-f", choices=["table", "json", "csv"], default="table", help="输出格式")
    p_list.add_argument("--output", "-o", help="写入文件而不是打印到终端")

    p_show = sub.add_parser("show", parents=[common], help="查看单个网络详情")
    p_show.add_argument("ssid", help="网络名称（支持模糊匹配）")
    p_show.add_argument("--copy", action="store_true", help="把密码复制到剪贴板")
    p_show.add_argument("--qr", action="store_true", help="同时显示二维码")

    p_export = sub.add_parser("export", parents=[common], help="导出报告")
    p_export.add_argument("-f", "--format", choices=["json", "csv", "txt", "html"], default="html")
    p_export.add_argument("-o", "--output", help="输出路径（默认自动命名）")
    p_export.add_argument("--search", "-s", default="", help="只导出匹配的网络")

    p_scan = sub.add_parser(
        "scan", parents=[common], help="扫描周围可见的无线网络（只读，不连接不破解）"
    )
    p_scan.add_argument("--open", action="store_true", help="只显示开放网络")
    p_scan.add_argument("--legacy", action="store_true", help="只显示 WEP/TKIP/WPA 老式加密")
    p_scan.add_argument("--band", choices=["2.4", "5", "6"], help="按频段过滤")
    p_scan.add_argument("--channel", type=int, help="按信道过滤")
    p_scan.add_argument("--saved", action="store_true", help="只显示本机已保存的网络")
    p_scan.add_argument("--sort", choices=["signal", "name", "channel"], default="signal", help="排序方式")
    p_scan.add_argument("-f", "--format", choices=["table", "json"], default="table", help="输出格式")
    p_scan.add_argument("-o", "--output", help="写入文件（配合 json）")
    p_scan.add_argument("--no-summary", action="store_true", help="只列网络，不显示环境评估")

    p_audit = sub.add_parser("audit", parents=[common], help="安全审计")
    p_audit.add_argument("-f", "--format", choices=["table", "json"], default="table")
    p_audit.add_argument("-o", "--output", help="写入文件")

    p_qr = sub.add_parser("qr", parents=[common], help="生成 WiFi 二维码")
    p_qr.add_argument("ssid")
    p_qr.add_argument("-o", "--output", help="保存为图片（.png 需 Pillow，.svg 无需）")
    p_qr.add_argument("--payload", action="store_true", help="同时打印二维码原始内容")

    sub.add_parser("gui", parents=[common], help="启动图形界面")
    sub.add_parser("doctor", parents=[common], help="环境与权限自检")
    return parser


# --------------------------------------------------------------------------- 公共逻辑


def _load_networks(args) -> tuple[Provider | None, list[WifiNetwork]]:
    provider = get_provider(getattr(args, "provider", "auto"))
    ok, reason = provider.available()
    if not ok:
        print(f"[错误] 数据源不可用：{reason}", file=sys.stderr)
        return None, []

    include_passwords = not getattr(args, "no_passwords", False)
    try:
        networks = provider.list_networks(include_passwords=include_passwords)
    except Exception as exc:  # noqa: BLE001
        print(f"[错误] 读取 WiFi 配置失败：{exc}", file=sys.stderr)
        return provider, []

    if not networks:
        print("[提示] 未发现任何已保存的 WiFi 配置。", file=sys.stderr)
    elif include_passwords and not any(n.has_password for n in networks):
        print(
            "[提示] 没有读取到任何密码：可能没有已保存密码，或当前权限不足"
            + ("（Linux 请使用 sudo 运行）" if sys.platform.startswith("linux") else "")
            + "。",
            file=sys.stderr,
        )
    return provider, networks


def _filtered(networks: list[WifiNetwork], args, provider: Provider | None = None) -> list[WifiNetwork]:
    from wifikey.audit import assess_password

    result = list(networks)
    query = (getattr(args, "search", "") or "").strip().casefold()
    if query:
        result = [
            n for n in result
            if query in n.ssid.casefold() or query in n.security.casefold() or query in (n.password or "").casefold()
        ]
    if getattr(args, "has_password", False):
        result = [n for n in result if n.has_password]
    if getattr(args, "weak", False):
        result = [n for n in result if n.password and assess_password(n.password).score < 55]
    if getattr(args, "open", False):
        result = [n for n in result if n.is_open]
    if getattr(args, "legacy", False):
        result = [n for n in result if n.is_wep or n.uses_tkip or n.is_wpa1_only]
    if getattr(args, "hidden", False):
        result = [n for n in result if n.hidden]
    if getattr(args, "current", False) and provider:
        current = provider.current_ssid()
        result = [n for n in result if current and n.ssid == current]

    sort_key = getattr(args, "sort", "name")
    if sort_key == "security":
        result.sort(key=lambda n: (n.security.casefold(), n.ssid.casefold()))
    elif sort_key == "score":
        result.sort(key=lambda n: (assess_password(n.password).score if n.has_password else 999, n.ssid.casefold()))
    else:
        result.sort(key=lambda n: n.ssid.casefold())
    return result


def _default_output(fmt: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    suffix = {"json": "json", "csv": "csv", "txt": "txt", "html": "html"}[fmt]
    return Path.cwd() / f"wifikey-report-{stamp}.{suffix}"


def _write(content: str, path: str | Path, encoding: str = "utf-8") -> None:
    target = save_text_file(content, path, encoding=encoding)
    print(f"已写入 {target}")


def _find_network(networks: list[WifiNetwork], keyword: str) -> tuple[WifiNetwork | None, list[WifiNetwork]]:
    key = keyword.strip().casefold()
    exact = [n for n in networks if n.ssid.casefold() == key]
    if exact:
        return exact[0], exact
    fuzzy = [n for n in networks if key in n.ssid.casefold()]
    if len(fuzzy) == 1:
        return fuzzy[0], fuzzy
    return None, fuzzy


def _reveal(args) -> bool:
    return not (getattr(args, "mask", False) or getattr(args, "no_passwords", False))


# --------------------------------------------------------------------------- 子命令


def cmd_list(args) -> int:
    provider, networks = _load_networks(args)
    if provider is None:
        return 1
    networks = _filtered(networks, args, provider)
    reveal = _reveal(args)

    if not networks:
        print("没有匹配的网络。")
        return 0

    fmt = args.format
    if fmt == "json":
        content = to_json(networks, reveal=reveal)
    elif fmt == "csv":
        content = to_csv(networks, reveal=reveal)
    else:
        current = provider.current_ssid() if networks else None
        content = render_network_table(networks, reveal=reveal, current=current)
        print(content)
        print(f"\n共 {len(networks)} 个网络" + ("（密码已隐藏）" if not reveal else ""))
        if not reveal:
            print("提示: 去掉 --mask / --no-passwords 可显示密码。")
        return 0

    if args.output:
        _write(content, args.output, encoding="utf-8-sig" if fmt == "csv" else "utf-8")
    else:
        print(content)
    return 0


def cmd_show(args) -> int:
    provider, networks = _load_networks(args)
    if provider is None:
        return 1
    net, matches = _find_network(networks, args.ssid)
    reveal = _reveal(args)
    if net is None:
        if matches:
            print(f"“{args.ssid}”匹配到 {len(matches)} 个网络，请指定更完整的名称：")
            for item in matches:
                print(f"  - {item.ssid}")
        else:
            print(f"未找到网络 “{args.ssid}”。")
            close = [n for n in networks if n.ssid.casefold()[:3] == args.ssid.casefold()[:3]][:5]
            if close:
                print("你是不是要找：" + "、".join(n.ssid for n in close))
        return 1

    report = audit_networks(networks)
    findings = [f for f in report.findings if f.ssid == net.ssid]
    print(render_detail(net, findings, reveal=reveal))

    if args.copy:
        if not net.password:
            print(c("没有可复制的密码。", "yellow"))
        elif copy_to_clipboard(net.password):
            print(c("密码已复制到剪贴板。", "green"))
        else:
            print(c("复制失败：当前环境不支持剪贴板。", "red"))

    if args.qr:
        print()
        print(_qr_text(net, reveal=reveal))
    return 0


def _qr_text(net: WifiNetwork, reveal: bool = True) -> str:
    payload = wifi_qr_payload(net)
    if not reveal:
        payload = wifi_qr_payload(
            WifiNetwork(ssid=net.ssid, password=None, security=net.security, hidden=net.hidden)
        )
    qr = render_qr_ascii(payload)
    if qr is None:
        return (
            "未安装 qrcode 依赖，无法绘制二维码。\n"
            "  pip install qrcode    然后重新运行\n"
            f"  二维码内容: {payload}"
        )
    return qr + f"\n  二维码内容: {payload}"


def cmd_export(args) -> int:
    provider, networks = _load_networks(args)
    if provider is None:
        return 1
    networks = _filtered(networks, args, provider)
    reveal = _reveal(args)
    if not networks:
        print("没有可导出的网络。")
        return 1

    fmt = args.format
    platform_name = provider.display_name
    if fmt == "json":
        content = to_json(networks, reveal=reveal, platform=platform_name)
        encoding = "utf-8"
    elif fmt == "csv":
        content = to_csv(networks, reveal=reveal)
        encoding = "utf-8-sig"
    elif fmt == "txt":
        content = to_txt(networks, reveal=reveal, platform=platform_name)
        encoding = "utf-8"
    else:
        content = to_html(networks, reveal=reveal, platform=platform_name)
        encoding = "utf-8"

    path = args.output or _default_output(fmt)
    _write(content, path, encoding=encoding)
    if fmt == "html":
        print("用浏览器打开该文件即可查看可搜索/可排序的报告。")
    if reveal:
        print(c("注意: 文件包含明文密码，请勿公开分享。", "yellow"))
    return 0


def cmd_scan(args) -> int:
    from wifikey.scanner import scan_environment, scan_networks

    provider = get_provider(getattr(args, "provider", "auto"))
    saved: list[WifiNetwork] = []
    try:
        ok, _reason = provider.available()
        if ok:
            saved = provider.list_networks(include_passwords=False)
    except Exception:  # noqa: BLE001
        saved = []

    networks, source = scan_networks({n.ssid for n in saved if n.ssid})
    if not networks:
        print(f"[提示] 没有扫描到周围可见的网络（来源: {source}）。")
        print("      请确认无线网卡已启用、WiFi 未被系统关闭，然后重试。")
        return 1

    result = list(networks)
    if getattr(args, "open", False):
        result = [n for n in result if n.is_open]
    if getattr(args, "legacy", False):
        result = [n for n in result if n.is_legacy]
    band = getattr(args, "band", None)
    if band:
        result = [n for n in result if n.band and n.band.startswith(band)]
    channel = getattr(args, "channel", None)
    if channel:
        result = [n for n in result if n.channel == channel]
    if getattr(args, "saved", False):
        result = [n for n in result if n.saved]

    sort_key = getattr(args, "sort", "signal")
    if sort_key == "name":
        result.sort(key=lambda n: (n.display_ssid.casefold(), -n.signal))
    elif sort_key == "channel":
        result.sort(key=lambda n: (n.channel if n.channel is not None else 999, -n.signal))
    else:
        result.sort(key=lambda n: -n.signal)

    summary = scan_environment(networks, saved)

    if getattr(args, "format", "table") == "json":
        payload = {
            "tool": "wifikey",
            "version": __version__,
            "scanned_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "source": source,
            "summary": {
                "total": summary.total,
                "open": summary.open_count,
                "wep": summary.wep_count,
                "legacy": summary.legacy_count,
                "wpa3": summary.wpa3_count,
                "saved": summary.saved_count,
                "bands": summary.bands,
                "overlap_24": summary.overlap_24,
                "findings": [
                    {"ssid": f.ssid, "code": f.code, "severity": f.severity, "title": f.title, "detail": f.detail}
                    for f in summary.findings
                ],
            },
            "networks": [asdict(n) for n in result],
        }
        content = json.dumps(payload, ensure_ascii=False, indent=2)
        if args.output:
            _write(content, args.output)
        else:
            print(content)
        return 0

    if not result:
        print("没有符合过滤条件的网络。")
        return 0

    current = None
    try:
        current = provider.current_ssid()
    except Exception:  # noqa: BLE001
        current = None
    print(render_scan_table(result, current_ssid=current))
    print(f"\n共 {len(result)} 个网络（扫描到 {len(networks)} 个可见网络）")
    if not getattr(args, "no_summary", False):
        print()
        print(render_scan_summary(summary, source=source, scanned_at=datetime.now().strftime("%H:%M:%S")))
    return 0


def cmd_audit(args) -> int:
    provider, networks = _load_networks(args)
    if provider is None:
        return 1
    if not networks:
        return 1
    report = audit_networks(networks)
    if args.format == "json":
        payload = {
            "tool": "wifikey",
            "version": __version__,
            "score": report.score,
            "stats": {k: v for k, v in report.stats.items() if k != "assessments"},
            "findings": [
                {"ssid": f.ssid, "code": f.code, "severity": f.severity, "title": f.title, "detail": f.detail}
                for f in report.findings
            ],
        }
        content = json.dumps(payload, ensure_ascii=False, indent=2)
    else:
        content = render_audit(report)
    if args.output:
        _write(content, args.output)
    else:
        print(content)
    return 0


def cmd_qr(args) -> int:
    provider, networks = _load_networks(args)
    if provider is None:
        return 1
    net, matches = _find_network(networks, args.ssid)
    if net is None:
        print(f"未找到网络 “{args.ssid}”" + (f"，匹配到: {'、'.join(m.ssid for m in matches)}" if matches else "。"))
        return 1
    reveal = _reveal(args)
    if not net.password and not net.is_open:
        print(c("该网络没有可读取的密码，二维码中不会包含密码。", "yellow"))
    payload = wifi_qr_payload(net if reveal else WifiNetwork(ssid=net.ssid, security=net.security))
    if args.payload:
        print(f"二维码内容: {payload}")

    if args.output:
        ok, msg = save_qr_image(payload, args.output)
        print(msg if ok else c(msg, "red"))
        return 0 if ok else 1

    qr = render_qr_ascii(payload)
    if qr is None:
        print("未安装 qrcode 依赖，无法绘制二维码。")
        print("  pip install qrcode")
        print(f"  二维码内容: {payload}")
        return 1
    print(qr)
    print(f"\n二维码内容: {payload}")
    return 0


def cmd_doctor(args) -> int:
    print(c("WiFiKey 环境自检", "bold"))
    print(f"  Python       {platform.python_version()} ({sys.executable})")
    print(f"  系统         {platform.system()} {platform.release()}")
    provider = get_provider(getattr(args, "provider", "auto"))
    ok, reason = provider.available()
    status = c("[OK]", "green") if ok else c("[!!]", "red")
    print(f"  {status} 数据源   {provider.display_name}" + (f" — {reason}" if reason else ""))

    if sys.platform == "win32":
        try:
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            print(f"  [--] 管理员权限 {'是' if is_admin else '否（读取当前用户配置无需管理员，通常不影响使用）'}")
        except Exception:
            pass
        print(f"  {('[OK]' if shutil.which('netsh') else '[!!]')} netsh     {'可用' if shutil.which('netsh') else '未找到'}")
    elif sys.platform.startswith("linux"):
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        print(f"  {('[OK]' if is_root else '[!!]')} root 权限 {'是' if is_root else '否（读取 NetworkManager / wpa_supplicant 配置通常需要 sudo）'}")
        print(f"  {('[OK]' if shutil.which('nmcli') else '[--]')} nmcli     {'可用' if shutil.which('nmcli') else '未安装'}")
    elif sys.platform == "darwin":
        print(f"  {('[OK]' if shutil.which('security') else '[!!]')} security  {'可用' if shutil.which('security') else '未找到'}")

    try:
        import qrcode  # noqa: F401

        qr_status = c("[OK] 已安装", "green")
    except ImportError:
        qr_status = c("[--] 未安装（二维码功能不可用，pip install qrcode）", "gray")
    print(f"  可选依赖 qrcode: {qr_status}")

    loaded_provider, networks = _load_networks(args)
    if loaded_provider:
        readable = sum(1 for n in networks if n.has_password)
        print(f"  [OK] 已读取 {len(networks)} 个网络，其中 {readable} 个含密码")
    print(c("  提示: 本工具只读取本机已保存的配置，不具备破解未保存网络的能力。", "gray"))
    return 0


def cmd_gui(args) -> int:
    try:
        from wifikey.gui import run_gui
    except ImportError as exc:
        print(f"无法启动图形界面：{exc}", file=sys.stderr)
        return 1
    return run_gui(provider_name=getattr(args, "provider", "auto"), no_passwords=getattr(args, "no_passwords", False))


def _configure_stdio() -> None:
    """避免在 GBK 等窄编码控制台（或重定向到管道）时，进度条字符导致 UnicodeEncodeError。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(errors="replace")
        except Exception:  # noqa: BLE001
            pass


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command or "list"
    if command in ("list", "ls"):
        args.command = "list"
        # 未指定子命令时补齐 list 的默认值
        for attr, default in (
            ("search", ""), ("has_password", False), ("weak", False), ("open", False),
            ("legacy", False), ("hidden", False), ("current", False),
            ("sort", "name"), ("format", "table"), ("output", None),
        ):
            if not hasattr(args, attr):
                setattr(args, attr, default)
        return cmd_list(args)

    handler = {
        "show": cmd_show,
        "scan": cmd_scan,
        "export": cmd_export,
        "audit": cmd_audit,
        "qr": cmd_qr,
        "gui": cmd_gui,
        "doctor": cmd_doctor,
    }.get(command)
    if handler is None:
        parser.print_help()
        return 2
    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\n已取消。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
