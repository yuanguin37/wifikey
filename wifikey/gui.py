"""Tkinter 图形界面。"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, font as tkfont, messagebox, ttk

from wifikey.audit import assess_password, audit_networks
from wifikey.clipboard import copy_to_clipboard
from wifikey.exporters import (
    save_qr_image,
    to_csv,
    to_html,
    to_json,
    wifi_qr_payload,
)
from wifikey.models import WifiNetwork
from wifikey.providers import get_provider
from wifikey.terminal import render_audit, render_detail, risk_of, scan_risk_of
from wifikey.textutil import strength_bar, strip_ansi

BG = "#0b1220"
PANEL = "#111a2c"
PANEL2 = "#0e1626"
LINE = "#22304d"
FG = "#e8eef9"
MUTED = "#91a4c2"
ACCENT = "#2dd4bf"
ACCENT_DARK = "#0f766e"
WARN = "#fbbf24"

FILTERS = ["全部网络", "仅含密码", "弱密码", "开放网络", "WEP/TKIP/WPA", "隐藏 SSID", "当前连接"]
SORTS = ["名称", "密码强度（弱→强）", "安全类型"]

SEV_TEXT = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示"}

# 按平台挑选可用的中文字体，避免在 macOS / Linux 上缺少 “Microsoft YaHei UI” 时回退到无中文字形的字体而显示方框
_FONT_CANDIDATES = (
    "Microsoft YaHei UI",
    "Microsoft YaHei",
    "PingFang SC",
    "Hiragino Sans GB",
    "Noto Sans CJK SC",
    "Source Han Sans SC",
    "WenQuanYi Micro Hei",
    "Segoe UI",
    "Helvetica",
)


def pick_ui_font(root: tk.Misc) -> str:
    """返回当前系统可用的界面字体名。"""
    try:
        families = {name.casefold() for name in tkfont.families(root)}
    except tk.TclError:
        return "TkDefaultFont"
    for name in _FONT_CANDIDATES:
        if name.casefold() in families:
            return name
    return "TkDefaultFont"


class WiFiKeyApp:
    def __init__(self, root: tk.Tk, provider_name: str = "auto", no_passwords: bool = False) -> None:
        self.root = root
        self.provider = get_provider(provider_name)
        self.no_passwords = no_passwords
        self.networks: list[WifiNetwork] = []
        self.current_ssid: str | None = None
        self._rows: dict[str, WifiNetwork] = {}
        self._queue: queue.Queue = queue.Queue()
        self._search_job: str | None = None
        self._scan_win: tk.Toplevel | None = None

        self.search_var = tk.StringVar()
        self.filter_var = tk.StringVar(value=FILTERS[0])
        self.sort_var = tk.StringVar(value=SORTS[0])
        self.reveal_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="正在读取 WiFi 配置…")

        self._build_ui()
        self.refresh()

    # ------------------------------------------------------------------ 界面

    def _build_ui(self) -> None:
        self.root.title("WiFiKey · 已保存 WiFi 密码管理器")
        self.root.configure(bg=BG)
        self.root.geometry("1080x680")
        self.root.minsize(900, 560)
        self.ui_font = pick_ui_font(self.root)

        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=BG, foreground=FG, fieldbackground=PANEL, bordercolor=LINE)
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=FG, font=(self.ui_font, 9))
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=(self.ui_font, 9))
        style.configure("Title.TLabel", background=BG, foreground=FG, font=(self.ui_font, 16, "bold"))
        style.configure("TButton", background=PANEL, foreground=FG, bordercolor=LINE, padding=(12, 6))
        style.map("TButton", background=[("active", "#1b2a45")], foreground=[("active", ACCENT)])
        style.configure("Accent.TButton", background=ACCENT, foreground="#04211d", bordercolor=ACCENT)
        style.map("Accent.TButton", background=[("active", "#14b8a6")])
        style.configure("TEntry", fieldbackground=PANEL2, foreground=FG, insertcolor=FG, bordercolor=LINE)
        style.configure("TCombobox", fieldbackground=PANEL2, background=PANEL, foreground=FG, arrowcolor=MUTED, bordercolor=LINE)
        style.map("TCombobox", fieldbackground=[("readonly", PANEL2)])
        style.configure(
            "Treeview",
            background=PANEL2,
            fieldbackground=PANEL2,
            foreground=FG,
            rowheight=30,
            borderwidth=0,
            font=(self.ui_font, 9),
        )
        style.map("Treeview", background=[("selected", "#17505c")], foreground=[("selected", "#f0fffd")])
        style.configure(
            "Treeview.Heading",
            background=PANEL,
            foreground=MUTED,
            relief="flat",
            padding=(8, 8),
            font=(self.ui_font, 9),
        )
        style.map("Treeview.Heading", background=[("active", "#1b2a45")])

        # 顶部标题
        header = ttk.Frame(self.root, padding=(20, 16, 20, 8))
        header.pack(fill="x")
        title_box = ttk.Frame(header)
        title_box.pack(side="left")
        ttk.Label(title_box, text="WiFiKey", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            title_box,
            text="读取本机已保存的 WiFi 配置 · 密码强度与安全审计 · 不进行任何破解行为",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(2, 0))
        self.platform_label = ttk.Label(header, text=self.provider.display_name, style="Muted.TLabel")
        self.platform_label.pack(side="right", padx=(0, 8))
        self.refresh_btn = ttk.Button(header, text="重新读取", style="Accent.TButton", command=self.refresh)
        self.refresh_btn.pack(side="right", padx=8)

        # 工具栏
        toolbar = ttk.Frame(self.root, padding=(20, 4, 20, 10))
        toolbar.pack(fill="x")
        ttk.Label(toolbar, text="搜索", style="Muted.TLabel").pack(side="left")
        entry = ttk.Entry(toolbar, textvariable=self.search_var, width=28)
        entry.pack(side="left", padx=(6, 14))
        self.search_var.trace_add("write", self._on_search_changed)

        ttk.Label(toolbar, text="筛选", style="Muted.TLabel").pack(side="left")
        filter_box = ttk.Combobox(toolbar, textvariable=self.filter_var, values=FILTERS, state="readonly", width=14)
        filter_box.pack(side="left", padx=(6, 14))
        filter_box.bind("<<ComboboxSelected>>", lambda _e: self.populate())

        ttk.Label(toolbar, text="排序", style="Muted.TLabel").pack(side="left")
        sort_box = ttk.Combobox(toolbar, textvariable=self.sort_var, values=SORTS, state="readonly", width=18)
        sort_box.pack(side="left", padx=(6, 14))
        sort_box.bind("<<ComboboxSelected>>", lambda _e: self.populate())

        self.reveal_check = ttk.Checkbutton(
            toolbar,
            text="显示密码",
            variable=self.reveal_var,
            command=self.populate,
        )
        if self.no_passwords:
            self.reveal_check.state(["disabled"])
        self.reveal_check.pack(side="left", padx=(4, 0))

        # 表格
        table_frame = ttk.Frame(self.root, padding=(20, 0, 20, 0))
        table_frame.pack(fill="both", expand=True)
        columns = ("idx", "ssid", "security", "cipher", "password", "strength", "risk")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        headings = {
            "idx": ("#", 44, "center"),
            "ssid": ("SSID", 230, "w"),
            "security": ("安全类型", 150, "w"),
            "cipher": ("加密", 80, "center"),
            "password": ("密码", 250, "w"),
            "strength": ("强度", 110, "center"),
            "risk": ("风险", 120, "center"),
        }
        for key, (text, width, anchor) in headings.items():
            self.tree.heading(key, text=text)
            self.tree.column(key, width=width, anchor=anchor, stretch=(key in ("ssid", "password")))
        self.tree.tag_configure("odd", background=PANEL2)
        self.tree.tag_configure("even", background="#101a2f")
        self.tree.tag_configure("masked", foreground=MUTED)
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda _e: self.copy_password())

        # 详情
        detail_frame = ttk.Frame(self.root, padding=(20, 10, 20, 0))
        detail_frame.pack(fill="x")
        self.detail = tk.Text(
            detail_frame,
            height=7,
            bg=PANEL,
            fg=FG,
            insertbackground=FG,
            relief="flat",
            font=(self.ui_font, 9),
            wrap="word",
            padx=14,
            pady=10,
            state="disabled",
        )
        self.detail.pack(fill="x")

        # 操作按钮
        actions = ttk.Frame(self.root, padding=(20, 10, 20, 8))
        actions.pack(fill="x")
        ttk.Button(actions, text="扫描周围网络", command=self.open_scan).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="复制密码", command=self.copy_password).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="生成二维码", command=self.show_qr).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="安全审计", command=self.show_audit).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="导出 HTML 报告", command=lambda: self.export("html")).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="导出 JSON", command=lambda: self.export("json")).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="导出 CSV", command=lambda: self.export("csv")).pack(side="left")
        self.status_label = ttk.Label(actions, textvariable=self.status_var, style="Muted.TLabel")
        self.status_label.pack(side="right")

        # 状态栏
        footer = ttk.Label(
            self.root,
            text="提示：密码仅从本机已保存配置中读取；隐藏密码后再截图或演示更安全。",
            style="Muted.TLabel",
            padding=(20, 6, 20, 10),
        )
        footer.pack(fill="x")

    # ------------------------------------------------------------------ 数据加载

    def refresh(self) -> None:
        self.refresh_btn.config(state="disabled")
        self.status_var.set("正在读取 WiFi 配置…")
        threading.Thread(target=self._load_worker, daemon=True).start()
        self.root.after(120, self._poll)

    def _load_worker(self) -> None:
        try:
            networks = self.provider.list_networks(include_passwords=not self.no_passwords)
            current = self.provider.current_ssid()
            self._queue.put(("ok", networks, current, None))
        except Exception as exc:  # noqa: BLE001
            self._queue.put(("error", [], None, exc))

    def _poll(self) -> None:
        try:
            status, networks, current, error = self._queue.get_nowait()
        except queue.Empty:
            self.root.after(120, self._poll)
            return
        self.refresh_btn.config(state="normal")
        if error is not None:
            self.status_var.set("读取失败")
            messagebox.showerror("读取失败", f"无法读取 WiFi 配置：\n{error}")
            return
        self.networks = networks
        self.current_ssid = current
        self.populate()
        readable = sum(1 for n in networks if n.has_password)
        weak = sum(1 for n in networks if n.password and assess_password(n.password).score < 55)
        extra = f" · 当前连接：{current}" if current else ""
        if self.no_passwords:
            self.status_var.set(f"共 {len(networks)} 个网络 · 密码未读取{extra}")
        else:
            self.status_var.set(f"共 {len(networks)} 个网络 · 可读取密码 {readable} · 弱密码 {weak}{extra}")
        if networks and not readable and not self.no_passwords:
            messagebox.showwarning(
                "未读取到密码",
                "没有读取到任何密码，可能是权限不足或配置中没有保存密码。\n"
                "Linux 请使用 sudo 运行；Windows 可尝试以管理员身份启动。",
            )

    # ------------------------------------------------------------------ 列表渲染

    def _on_search_changed(self, *_args) -> None:
        if self._search_job:
            self.root.after_cancel(self._search_job)
        self._search_job = self.root.after(180, self.populate)

    def visible_networks(self) -> list[WifiNetwork]:
        items = list(self.networks)
        query = self.search_var.get().strip().casefold()
        if query:
            items = [
                n for n in items
                if query in n.ssid.casefold()
                or query in n.security.casefold()
                or query in (n.password or "").casefold()
            ]

        mode = self.filter_var.get()
        if mode == "仅含密码":
            items = [n for n in items if n.has_password]
        elif mode == "弱密码":
            items = [n for n in items if n.password and assess_password(n.password).score < 55]
        elif mode == "开放网络":
            items = [n for n in items if n.is_open]
        elif mode == "WEP/TKIP/WPA":
            items = [n for n in items if n.is_wep or n.uses_tkip or n.is_wpa1_only]
        elif mode == "隐藏 SSID":
            items = [n for n in items if n.hidden]
        elif mode == "当前连接":
            items = [n for n in items if self.current_ssid and n.ssid == self.current_ssid]

        sort_mode = self.sort_var.get()
        if sort_mode == "密码强度（弱→强）":
            items.sort(key=lambda n: (assess_password(n.password).score if n.has_password else 999, n.ssid.casefold()))
        elif sort_mode == "安全类型":
            items.sort(key=lambda n: (n.security.casefold(), n.ssid.casefold()))
        else:
            items.sort(key=lambda n: n.ssid.casefold())
        return items

    def populate(self) -> None:
        previous = self._selected_network()
        self.tree.delete(*self.tree.get_children())
        self._rows.clear()
        reveal = self.reveal_var.get() and not self.no_passwords
        for index, net in enumerate(self.visible_networks()):
            iid = f"n{index}"
            self._rows[iid] = net
            if net.password:
                pwd = net.password if reveal else "••••••••"
            elif net.is_open:
                pwd = "（开放网络）"
            else:
                pwd = "（未读取）"
            assessment = assess_password(net.password)
            strength = f"{strength_bar(assessment.score, 5)} {assessment.score}" if net.password else "—"
            risk = risk_of(net)
            risk_text = f"{SEV_TEXT[risk[0]]}·{risk[1]}" if risk else "正常"
            ssid = net.ssid + (" ★" if self.current_ssid and net.ssid == self.current_ssid else "")
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(index + 1, ssid, net.security, net.cipher or "—", pwd, strength, risk_text),
                tags=("even" if index % 2 == 0 else "odd",) + (("masked",) if net.password and not reveal else ()),
            )
        if not self.networks:
            self.detail.configure(state="normal")
            self.detail.delete("1.0", "end")
            self.detail.insert("1.0", "未发现已保存的 WiFi 配置。")
            self.detail.configure(state="disabled")
            return

        # 切换“显示密码”等操作后保持当前选中项
        if previous is not None:
            for iid, net in self._rows.items():
                if net is previous:
                    self.tree.selection_set(iid)
                    self.tree.focus(iid)
                    self.tree.see(iid)
                    self._on_select()
                    break

    def _selected_network(self) -> WifiNetwork | None:
        iid = self.tree.focus()
        if iid in self._rows:
            return self._rows[iid]
        selection = self.tree.selection()
        if selection:
            return self._rows.get(selection[0])
        return None

    def _on_select(self, _event=None) -> None:
        net = self._selected_network()
        if not net:
            return
        report = audit_networks(self.networks)
        findings = [f for f in report.findings if f.ssid == net.ssid]
        text = render_detail(net, findings, reveal=self.reveal_var.get() and not self.no_passwords)
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", strip_ansi(text))
        self.detail.configure(state="disabled")

    # ------------------------------------------------------------------ 操作

    def copy_password(self) -> None:
        net = self._selected_network()
        if not net:
            messagebox.showinfo("提示", "请先在列表中选择一个网络。")
            return
        if not net.password:
            messagebox.showinfo("提示", "该网络没有可读取的密码。")
            return
        if copy_to_clipboard(net.password):
            self.status_var.set(f"已复制 {net.ssid} 的密码到剪贴板")
        else:
            messagebox.showwarning("复制失败", "当前环境不支持写入剪贴板。")

    def show_qr(self) -> None:
        net = self._selected_network()
        if not net:
            messagebox.showinfo("提示", "请先在列表中选择一个网络。")
            return
        payload = wifi_qr_payload(net)

        top = tk.Toplevel(self.root)
        top.title(f"二维码 · {net.ssid}")
        top.configure(bg=BG)
        top.geometry("420x560")
        top.transient(self.root)

        ttk.Label(top, text=net.ssid, style="Title.TLabel").pack(pady=(18, 4))
        ttk.Label(
            top,
            text="用手机相机扫描即可连接（密码仅用于生成本地二维码）",
            style="Muted.TLabel",
        ).pack(pady=(0, 12))

        canvas = tk.Canvas(top, width=340, height=340, bg="#ffffff", highlightthickness=0)
        canvas.pack()

        try:
            import qrcode

            qr = qrcode.QRCode(border=2, error_correction=qrcode.constants.ERROR_CORRECT_M)
            qr.add_data(payload)
            qr.make(fit=True)
            matrix = qr.get_matrix()
            modules = len(matrix)
            box = max(1, 340 // modules)
            offset = (340 - modules * box) // 2
            for y, row in enumerate(matrix):
                for x, dark in enumerate(row):
                    if dark:
                        canvas.create_rectangle(
                            offset + x * box,
                            offset + y * box,
                            offset + (x + 1) * box,
                            offset + (y + 1) * box,
                            fill="#0b1220",
                            outline="",
                        )
        except ImportError:
            canvas.create_text(
                170,
                150,
                text="未安装 qrcode 依赖\npip install qrcode",
                fill="#334155",
                font=(self.ui_font, 12),
                justify="center",
            )

        info = ttk.Label(top, text=payload, style="Muted.TLabel", wraplength=360)
        info.pack(pady=10)

        buttons = ttk.Frame(top)
        buttons.pack(pady=(4, 14))
        ttk.Button(buttons, text="复制二维码内容", command=lambda: self._copy_text(payload)).pack(side="left", padx=6)
        ttk.Button(buttons, text="保存图片", command=lambda: self._save_qr(payload, net.ssid)).pack(side="left", padx=6)
        ttk.Button(buttons, text="关闭", command=top.destroy).pack(side="left", padx=6)

    def _copy_text(self, text: str) -> None:
        if copy_to_clipboard(text):
            self.status_var.set("二维码内容已复制")
        else:
            messagebox.showwarning("复制失败", "当前环境不支持写入剪贴板。")

    def _save_qr(self, payload: str, ssid: str) -> None:
        safe = "".join(ch for ch in ssid if ch.isalnum() or ch in "-_") or "wifi"
        path = filedialog.asksaveasfilename(
            title="保存二维码",
            defaultextension=".png",
            initialfile=f"wifi-{safe}.png",
            filetypes=[("PNG 图片", "*.png"), ("SVG 矢量图", "*.svg")],
        )
        if not path:
            return
        ok, msg = save_qr_image(payload, path)
        if ok:
            messagebox.showinfo("已保存", msg)
        else:
            messagebox.showerror("保存失败", msg)

    def show_audit(self) -> None:
        if not self.networks:
            messagebox.showinfo("提示", "没有可审计的网络。")
            return
        report = audit_networks(self.networks)
        top = tk.Toplevel(self.root)
        top.title("安全审计")
        top.configure(bg=BG)
        top.geometry("780x560")
        top.transient(self.root)
        text = tk.Text(
            top,
            bg=PANEL,
            fg=FG,
            relief="flat",
            font=(self.ui_font, 10),
            wrap="word",
            padx=16,
            pady=14,
        )
        text.pack(fill="both", expand=True, padx=14, pady=14)
        text.insert("1.0", strip_ansi(render_audit(report)))
        text.configure(state="disabled")
        ttk.Button(top, text="关闭", command=top.destroy).pack(pady=(0, 14))

    # ------------------------------------------------------------------ 周围网络扫描

    def open_scan(self) -> None:
        from wifikey.scanner import scan_environment, scan_networks

        try:
            if self._scan_win is not None and self._scan_win.winfo_exists():
                self._scan_win.deiconify()
                self._scan_win.lift()
                return
        except tk.TclError:
            self._scan_win = None

        top = tk.Toplevel(self.root)
        self._scan_win = top
        top.title("扫描周围网络 · WiFiKey")
        top.configure(bg=BG)
        top.geometry("1020x640")
        top.transient(self.root)

        ttk.Label(top, text="周围可见的无线网络", style="Title.TLabel").pack(pady=(16, 2))
        ttk.Label(
            top,
            text="只读扫描，与系统 WiFi 列表相同 · 不连接、不破解任何网络 · 无法查看未保存网络的密码",
            style="Muted.TLabel",
        ).pack(pady=(0, 8))

        status_var = tk.StringVar(value="点击“重新扫描”获取周围网络列表。")
        ttk.Label(top, textvariable=status_var, style="Muted.TLabel", wraplength=940, justify="left").pack(
            fill="x", padx=18
        )

        body = ttk.Frame(top)
        body.pack(fill="both", expand=True, padx=18, pady=10)
        columns = ("idx", "ssid", "signal", "channel", "band", "security", "saved", "risk")
        tree = ttk.Treeview(body, columns=columns, show="headings", selectmode="browse")
        headings = {
            "idx": ("#", 40, "center"),
            "ssid": ("SSID", 240, "w"),
            "signal": ("信号", 110, "center"),
            "channel": ("信道", 60, "center"),
            "band": ("频段", 80, "center"),
            "security": ("安全类型", 170, "w"),
            "saved": ("已保存", 80, "center"),
            "risk": ("风险", 110, "center"),
        }
        for key, (text, width, anchor) in headings.items():
            tree.heading(key, text=text)
            tree.column(key, width=width, anchor=anchor, stretch=(key == "ssid"))
        tree.tag_configure("odd", background=PANEL2)
        tree.tag_configure("even", background="#101a2f")
        tree.tag_configure("opennet", foreground=WARN)
        scrollbar = ttk.Scrollbar(body, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        scan_queue: queue.Queue = queue.Queue()

        def worker() -> None:
            try:
                saved = self.provider.list_networks(include_passwords=False)
                networks, source = scan_networks({n.ssid for n in saved if n.ssid})
                summary = scan_environment(networks, saved)
                scan_queue.put(("ok", networks, summary, source))
            except Exception as exc:  # noqa: BLE001
                scan_queue.put(("error", str(exc)))

        def poll() -> None:
            if not top.winfo_exists():  # 窗口在扫描过程中被关闭
                return
            try:
                status, *payload = scan_queue.get_nowait()
            except queue.Empty:
                top.after(150, poll)
                return
            scan_btn.config(state="normal")
            if status == "error":
                status_var.set("扫描失败")
                messagebox.showerror("扫描失败", f"无法扫描周围网络：\n{payload[0]}", parent=top)
                return
            networks, summary, source = payload
            tree.delete(*tree.get_children())
            for index, net in enumerate(networks):
                risk = scan_risk_of(net)
                risk_text = f"{SEV_TEXT[risk[0]]}·{risk[1]}" if risk else "—"
                saved_text = "★ 已保存" if net.saved else ""
                tree.insert(
                    "",
                    "end",
                    values=(
                        index + 1,
                        net.display_ssid,
                        f"{strength_bar(net.signal, 5)} {net.signal}%",
                        net.channel if net.channel is not None else "—",
                        net.band or "—",
                        net.security,
                        saved_text,
                        risk_text,
                    ),
                    tags=("even" if index % 2 == 0 else "odd",) + (("opennet",) if net.is_open else ()),
                )
            bands_text = " · ".join(f"{k} {v}" for k, v in sorted(summary.bands.items()))
            findings_text = ""
            if summary.findings:
                parts = []
                for f in summary.findings:
                    mark = SEV_TEXT.get(f.severity, "提示")
                    name = f"{f.ssid}: " if f.ssid else ""
                    parts.append(f"[{mark}] {name}{f.title}")
                findings_text = "\n" + "\n".join(f"  {p}" for p in parts)
            status_var.set(
                f"可见网络 {summary.total} 个"
                + (f"（{bands_text}）" if bands_text else "")
                + f" · 开放 {summary.open_count} · WEP {summary.wep_count} · 老式加密 {summary.legacy_count}"
                + f" · WPA3 {summary.wpa3_count} · 本机已保存 {summary.saved_count} · 来源 {source}"
                + findings_text
            )
            if not networks:
                status_var.set("没有扫描到周围可见的网络，请确认无线网卡已启用。")

        def start_scan() -> None:
            scan_btn.config(state="disabled")
            status_var.set("正在扫描…")
            threading.Thread(target=worker, daemon=True).start()
            top.after(150, poll)

        buttons = ttk.Frame(top)
        buttons.pack(pady=(0, 14))
        scan_btn = ttk.Button(buttons, text="重新扫描", style="Accent.TButton", command=start_scan)
        scan_btn.pack(side="left", padx=6)
        ttk.Button(buttons, text="关闭", command=top.destroy).pack(side="left", padx=6)

        top.protocol("WM_DELETE_WINDOW", top.destroy)
        start_scan()

    def export(self, fmt: str) -> None:
        if not self.networks:
            messagebox.showinfo("提示", "没有可导出的网络。")
            return
        reveal = self.reveal_var.get() and not self.no_passwords
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        default_name = f"wifikey-report-{stamp}.{fmt}"
        filetypes = {
            "html": [("HTML 报告", "*.html")],
            "json": [("JSON 数据", "*.json")],
            "csv": [("CSV 表格", "*.csv")],
        }[fmt]
        path = filedialog.asksaveasfilename(
            title="导出报告", defaultextension=f".{fmt}", initialfile=default_name, filetypes=filetypes
        )
        if not path:
            return
        platform_name = self.provider.display_name
        if fmt == "html":
            content = to_html(self.networks, reveal=reveal, platform=platform_name)
        elif fmt == "json":
            content = to_json(self.networks, reveal=reveal, platform=platform_name)
        else:
            content = to_csv(self.networks, reveal=reveal)
        encoding = "utf-8-sig" if fmt == "csv" else "utf-8"
        Path(path).write_text(content, encoding=encoding)
        if reveal and fmt != "csv":
            messagebox.showwarning("导出完成", f"已导出到：\n{path}\n\n文件包含明文密码，请妥善保管。")
        else:
            messagebox.showinfo("导出完成", f"已导出到：\n{path}")


def run_gui(provider_name: str = "auto", no_passwords: bool = False) -> int:
    try:
        import tkinter  # noqa: F401
    except ImportError:
        print("当前 Python 未安装 tkinter，无法启动图形界面。", file=__import__("sys").stderr)
        return 1

    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    root = tk.Tk()
    try:
        WiFiKeyApp(root, provider_name=provider_name, no_passwords=no_passwords)
    except Exception as exc:  # noqa: BLE001
        messagebox.showerror("启动失败", str(exc))
        root.destroy()
        return 1
    root.mainloop()
    return 0
