"""tkinter 图形界面：选择场景、观察三方通信过程、对比攻击与防御结果。

界面构成：
  * 顶部：实验进度、场景配置与操作按钮
  * 左侧：Alice | Evil | Bob 三泳道时序图（箭头=线路上的报文，方框=各方的关键行为）
          其下为三方"视角"——各自实际看到/收到的内容，以及各方持有的会话密钥指纹
  * 右侧：事件日志与结果判定

线程安全：世界（World）的推进都在主线程完成（速度很快）；RSA 密钥生成与"对比全部场景"
这类耗时任务在工作线程里运行，结果经 queue.Queue 返回，由 root.after() 轮询并在主线程更新界面。
"""

import sys
import tkinter as tk
from collections import deque
from tkinter import font as tkfont
from tkinter import messagebox, ttk

from ..proto import events as ev
from ..proto.attacker import MODE_LABELS, EvilMode
from ..proto.identities import KeyRing, generate_keyring
from ..proto.messages import WireError, decode
from ..proto.profiles import SecurityProfile
from ..proto.scenarios import ALICE_TEXT, BOB_TEXT, SCENARIOS, World, run_all
from .worker import BackgroundRunner

LANES = ("Alice", "Evil", "Bob")
LANE_COLORS = {"Alice": "#1d57b6", "Evil": "#ac3449", "Bob": "#146953"}
LANE_FILLS = {"Alice": "#edf4ff", "Evil": "#fdf0f3", "Bob": "#eaf7f2"}
BG, SURFACE, BORDER, INK = "#edf1f7", "#ffffff", "#dce3ee", "#18243a"
HEADER, HEADER_BADGE = "#172640", "#2a3e62"
ACCENT, ACCENT_HOVER, ACCENT_PRESSED = "#394dbb", "#3042a5", "#273784"
NORMAL, DANGER, WARN, GOOD, MUTED, KEYC = "#354762", "#aa2944", "#855211", "#146953", "#53647d", "#613cb0"
NOTE_FILLS = {DANGER: LANE_FILLS["Evil"], WARN: "#fff4e1", GOOD: LANE_FILLS["Bob"], KEYC: "#f3edff"}
ROW_H, TOP_Y = 40, 30
POLL_MS = 50
AUTOPLAY_MS = 450
FONT_CANDIDATES = ("Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC",
                   "WenQuanYi Micro Hei", "SimHei")
LOG_TAG_COLORS = {ev.ALERT: DANGER, ev.MODIFY: DANGER, ev.REPLAY: WARN, ev.SPY: WARN, ev.KEY: KEYC,
                  ev.APP: GOOD, ev.INTERCEPT: "#a04000", ev.FORWARD: MUTED, ev.NET: MUTED,
                  ev.RECV: MUTED, ev.FAULT: WARN}
CUSTOM = "（自定义配置）"


class App:
    def __init__(self, root: tk.Tk, rsa_bits: int = 2048, keyring: KeyRing = None):
        self.root, self.rsa_bits, self.keyring = root, rsa_bits, None
        self.runner = BackgroundRunner()
        self.world = None
        self._autoplay_job = None
        self._finished = False
        self._ops: list = []                # 泳道图绘制指令
        self._follow_timeline = True
        self._evil_arrow_colors: deque = deque()
        self._keygen_pending = False
        self._comparison_pending = False
        self._poll_job = None
        self._setup_fonts()
        self._setup_style()
        self._build_ui()
        self.scenario_var.set(SCENARIOS[0].title)
        self._on_scenario_selected()
        self._poll()
        if keyring is None:
            self._generate_keys()
        else:
            self._on_keys_ready(keyring)

    # ------------------------------------------------------------ 界面搭建
    def _setup_fonts(self) -> None:
        families = set(tkfont.families(self.root))
        family = next((f for f in FONT_CANDIDATES if f in families), None)
        if family:
            for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
                tkfont.nametofont(name).configure(family=family)
        self.font_family = family or tkfont.nametofont("TkDefaultFont").actual("family")
        self.small_font = tkfont.Font(root=self.root, family=self.font_family, size=9)
        self.bold_font = (self.font_family, 10, "bold")
        self.title_font = (self.font_family, 19, "bold")
        self.section_font = (self.font_family, 11, "bold")
        self.mono_font = ("Consolas" if "Consolas" in families else tkfont.nametofont("TkFixedFont").actual("family"), 10)

    def _setup_style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        self.root.configure(background=BG)
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=SURFACE)
        style.configure("TLabel", background=BG, foreground=INK)
        style.configure("Panel.TLabel", background=SURFACE)
        style.configure("Section.TLabel", background=SURFACE, font=self.section_font)
        style.configure("Hint.TLabel", background=SURFACE, foreground=MUTED, font=self.small_font)
        style.configure("Status.TLabel", padding=(4, 3), foreground=MUTED, font=self.small_font)
        style.configure("TButton", background=SURFACE, foreground=INK, bordercolor=BORDER,
                        lightcolor=SURFACE, darkcolor=SURFACE, focuscolor=ACCENT, padding=(10, 6))
        style.map("TButton", background=[("disabled", BG), ("pressed", "#dce6f9"), ("active", "#edf3ff")],
                  foreground=[("disabled", MUTED)], bordercolor=[("focus", ACCENT), ("active", ACCENT)])
        style.configure("Primary.TButton", background=ACCENT, foreground=SURFACE, bordercolor=ACCENT,
                        lightcolor=ACCENT, darkcolor=ACCENT, focuscolor=SURFACE, font=self.bold_font)
        style.map("Primary.TButton", background=[("disabled", BORDER), ("pressed", ACCENT_PRESSED),
                                                  ("active", ACCENT_HOVER)])
        for control in ("TEntry", "TCombobox"):
            style.configure(control, fieldbackground=SURFACE, background=SURFACE, foreground=INK,
                            bordercolor=BORDER, lightcolor=SURFACE, darkcolor=SURFACE, padding=(7, 3),
                            selectbackground=ACCENT, selectforeground=SURFACE, arrowcolor=MUTED)
            style.map(control, fieldbackground=[("readonly", SURFACE)], bordercolor=[("focus", ACCENT)])
        style.configure("TCheckbutton", background=SURFACE, foreground=INK, focuscolor=ACCENT,
                        indicatorbackground=SURFACE, indicatorforeground=SURFACE, indicatormargin=(0, 0, 5, 0))
        style.map("TCheckbutton", background=[("active", SURFACE)],
                  indicatorbackground=[("selected", ACCENT)], indicatorforeground=[("selected", SURFACE)])
        style.configure("TNotebook", background=BG, bordercolor=BG, lightcolor=BG, darkcolor=BG,
                        borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure("TNotebook.Tab", background=BG, foreground=MUTED, bordercolor=BORDER,
                        lightcolor=BG, darkcolor=BG, focuscolor=ACCENT, padding=(14, 8))
        style.map("TNotebook.Tab", background=[("selected", SURFACE), ("active", "#e4ebf8")],
                  foreground=[("selected", ACCENT), ("active", INK)],
                  lightcolor=[("selected", SURFACE)], darkcolor=[("selected", SURFACE)],
                  padding=[("selected", (14, 8))])
        style.configure("TPanedwindow", background=BG, sashwidth=10)
        style.layout("Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {"sticky": "ns",
                     "children": [("Vertical.Scrollbar.thumb", {"sticky": "nswe"})]})])
        style.configure("Vertical.TScrollbar", background=BORDER, troughcolor=SURFACE, gripcount=0,
                        bordercolor=SURFACE, lightcolor=BORDER, darkcolor=BORDER, arrowsize=9)
        style.map("Vertical.TScrollbar", background=[("active", "#aab9d0"), ("pressed", "#889dbb")])
        style.configure("Treeview", background=SURFACE, fieldbackground=SURFACE, foreground=INK,
                        borderwidth=0, rowheight=self.small_font.metrics("linespace") + 12)
        style.configure("Treeview.Heading", background=HEADER, foreground=SURFACE, font=self.bold_font,
                        bordercolor=HEADER, lightcolor=HEADER, darkcolor=HEADER, padding=(8, 7))
        style.map("Treeview.Heading", background=[("active", HEADER_BADGE)])
        style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", SURFACE)])

    @staticmethod
    def _card(parent, padding=0) -> tk.Frame:
        return tk.Frame(parent, background=SURFACE, highlightbackground=BORDER, highlightthickness=1,
                        padx=padding, pady=padding)

    def _build_ui(self) -> None:
        r = self.root
        r.title("中间人攻击与防御实验器")
        # 窗口尺寸随屏幕自适应（高 DPI 缩放下 tkinter 的像素数会被放大）
        w = min(1360, r.winfo_screenwidth() - 60)
        h = min(860, r.winfo_screenheight() - 72)
        r.geometry(f"{w}x{h}+20+20")
        r.minsize(min(1000, w), min(690, h))

        self.scenario_var = tk.StringVar()
        self.auth_var, self.mac_var, self.replay_var = tk.BooleanVar(), tk.BooleanVar(), tk.BooleanVar()
        self.mode_var = tk.StringVar()
        self.alice_text_var = tk.StringVar(value=ALICE_TEXT)
        self.bob_text_var = tk.StringVar(value=BOB_TEXT)
        self.tamper_old_var, self.tamper_new_var = tk.StringVar(value="100"), tk.StringVar(value="10000")
        self.verbose_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="就绪")

        self.phase_var = tk.StringVar(value="准备中")
        self.empty_labels = {}

        hero = tk.Frame(r, background=HEADER, padx=18, pady=12)
        hero.pack(fill="x", padx=16, pady=(14, 10))
        mark = tk.Canvas(hero, width=36, height=36, highlightthickness=0, background=HEADER)
        mark.pack(side="left", padx=(0, 12))
        mark.create_rectangle(1, 1, 35, 35, fill=HEADER_BADGE, outline="")
        for x, y in ((10, 12), (26, 12), (18, 25)):
            mark.create_oval(x - 2, y - 2, x + 2, y + 2, fill="#dbe5ff", outline="")
        mark.create_line(13, 12, 23, 12, fill="#a9bcff", width=2)
        mark.create_line(11, 15, 16, 22, fill="#a9bcff", width=2)
        mark.create_line(25, 15, 20, 22, fill="#a9bcff", width=2)
        tk.Label(hero, text=r.title(), background=HEADER, foreground=SURFACE, font=self.title_font).pack(side="left")
        tk.Label(hero, textvariable=self.phase_var, width=8, background=HEADER_BADGE,
                 foreground="#e0e9ff", font=self.small_font, padx=8, pady=5).pack(side="right")

        self._build_settings(r)
        bar = self._card(r, padding=7)
        bar.pack(fill="x", padx=16, pady=(0, 10))
        self.buttons = {}
        for key, text, cmd in (("reset", "重置", self.reset), ("step", "单步", self.step),
                               ("auto", "自动播放", self.toggle_autoplay), ("run", "一键运行", self.run_all_steps),
                               ("replay", "Evil 立即重放", self.evil_replay),
                               ("compare", "对比全部场景", self.compare_all),
                               ("keys", "重新生成 RSA 密钥", self._generate_keys)):
            style = "Primary.TButton" if key == "run" else "TButton"
            b = ttk.Button(bar, text=text, command=cmd, style=style)
            b.pack(side="left", padx=(14 if key == "replay" else 0, 6))
            self.buttons[key] = b

        ttk.Label(r, textvariable=self.status_var, style="Status.TLabel", anchor="w").pack(
            side="bottom", fill="x", padx=16, pady=(4, 6))
        paned = ttk.PanedWindow(r, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=16)
        left = ttk.Frame(paned)
        right = ttk.Frame(paned)
        paned.add(left, weight=3)
        paned.add(right, weight=2)
        self._build_timeline(left)
        self._build_inspector(right)

    def _build_settings(self, parent) -> None:
        top = self._card(parent, padding=10)
        top.pack(fill="x", padx=16, pady=(0, 8))
        top.columnconfigure((0, 1), weight=1, uniform="settings")
        preset = ttk.Frame(top, style="Panel.TFrame")
        preset.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        preset.columnconfigure(1, weight=1)
        ttk.Label(preset, text="场景", style="Section.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.scenario_box = ttk.Combobox(preset, textvariable=self.scenario_var, state="readonly", width=24,
                                         values=[s.title for s in SCENARIOS])
        self.scenario_box.grid(row=0, column=1, sticky="ew")
        self.scenario_box.bind("<<ComboboxSelected>>", lambda _e: self._on_scenario_selected())
        self.desc_label = ttk.Label(preset, style="Hint.TLabel", wraplength=410, justify="left")
        self.desc_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=(5, 0))
        preset.bind("<Configure>", lambda e: self.desc_label.configure(wraplength=max(e.width - 2, 1)))

        security = ttk.Frame(top, style="Panel.TFrame")
        security.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        security.columnconfigure(1, weight=1)
        ttk.Label(security, text="Evil 行为", style="Panel.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.mode_box = ttk.Combobox(security, textvariable=self.mode_var, state="readonly", width=22,
                                     values=list(MODE_LABELS.values()))
        self.mode_box.grid(row=0, column=1, sticky="ew")
        self.mode_box.bind("<<ComboboxSelected>>", lambda _e: self._on_config_changed())
        ttk.Label(security, text="防御", style="Panel.TLabel").grid(row=1, column=0, sticky="w", pady=(5, 0))
        defenses = ttk.Frame(security, style="Panel.TFrame")
        defenses.grid(row=1, column=1, sticky="w", pady=(5, 0))
        for label, var in (("签名认证 DH", self.auth_var), ("HMAC 完整性", self.mac_var),
                           ("序号防重放", self.replay_var)):
            ttk.Checkbutton(defenses, text=label, variable=var, command=self._on_config_changed).pack(
                side="left", padx=(0, 9))

        tk.Frame(top, background=BORDER, height=1).grid(row=1, column=0, columnspan=2, sticky="ew", pady=7)
        messages = ttk.Frame(top, style="Panel.TFrame")
        messages.grid(row=2, column=0, columnspan=2, sticky="ew")
        messages.columnconfigure((0, 1, 2), weight=1, uniform="messages")
        for i, (title, var) in enumerate((("Alice 消息", self.alice_text_var), ("Bob 回复", self.bob_text_var),
                                          ("Evil 篡改规则", self.tamper_old_var))):
            field = ttk.Frame(messages, style="Panel.TFrame")
            field.grid(row=0, column=i, sticky="ew", padx=(0, 12 if i < 2 else 0))
            ttk.Label(field, text=title, style="Hint.TLabel").pack(anchor="w", pady=(0, 3))
            ttk.Entry(field, textvariable=var, width=9 if i == 2 else 16).pack(side="left", fill="x", expand=True)
            if i == 2:
                ttk.Label(field, text="→", style="Panel.TLabel", padding=(8, 0)).pack(side="left")
                ttk.Entry(field, textvariable=self.tamper_new_var, width=9).pack(side="left", fill="x", expand=True)

    def _build_timeline(self, parent) -> None:
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        lane_frame = self._card(parent)
        lane_frame.grid(row=0, column=0, sticky="nsew")
        heading = ttk.Frame(lane_frame, style="Panel.TFrame", padding=(12, 6))
        heading.grid(row=0, column=0, columnspan=2, sticky="ew")
        ttk.Label(heading, text="通信时序", style="Section.TLabel").pack(side="left")
        ttk.Label(heading, text="时间向下", style="Hint.TLabel").pack(side="right")
        lane_frame.columnconfigure(0, weight=1)
        lane_frame.rowconfigure(2, weight=1)
        self.header = tk.Canvas(lane_frame, background=SURFACE, highlightthickness=0, height=36, width=1)
        self.header.grid(row=1, column=0, sticky="ew")
        self.canvas = tk.Canvas(lane_frame, background=SURFACE, highlightthickness=0, height=100, width=1)
        vbar = ttk.Scrollbar(lane_frame, orient="vertical", command=self._scroll_timeline)
        self.canvas.configure(yscrollcommand=vbar.set, yscrollincrement=ROW_H // 2)
        vbar.grid(row=2, column=1, sticky="ns")
        self.canvas.grid(row=2, column=0, sticky="nsew")
        self.canvas.bind("<Configure>", lambda _e: self._redraw())
        self.canvas.bind("<MouseWheel>", self._wheel_timeline)
        self.canvas.bind("<Button-4>", lambda _e: self._scroll_timeline("scroll", -2, "units"))
        self.canvas.bind("<Button-5>", lambda _e: self._scroll_timeline("scroll", 2, "units"))

        views = ttk.Frame(parent)
        views.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        self.view_text, self.key_labels = {}, {}
        for i, who in enumerate(LANES):
            col = self._card(views)
            col.grid(row=0, column=i, sticky="nsew", padx=(0, 6 if i < 2 else 0))
            views.columnconfigure(i, weight=1, uniform="perspectives")
            tk.Label(col, text=f"{who} 的视角", font=self.bold_font, foreground=LANE_COLORS[who],
                     background=LANE_FILLS[who], anchor="w", padx=9, pady=4).pack(fill="x")
            self.view_text[who] = self._make_text(col, height=3, width=1, padding=8)
        parent.bind("<Configure>", self._resize_perspectives)

        keys = self._card(parent, padding=5)
        keys.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        ttk.Label(keys, text="会话密钥指纹", style="Section.TLabel").grid(row=0, column=0, columnspan=4, sticky="w", padx=3)
        for i, (key, label) in enumerate((("Alice", "Alice"), ("Evil↔Alice", "Evil / Alice"),
                                          ("Evil↔Bob", "Evil / Bob"), ("Bob", "Bob"))):
            keys.columnconfigure(i, weight=1, uniform="fingerprints")
            ttk.Label(keys, text=label, style="Hint.TLabel").grid(row=1, column=i, sticky="w", padx=3, pady=(3, 0))
            lbl = ttk.Label(keys, text="—", style="Panel.TLabel", foreground=MUTED, font=self.mono_font)
            lbl.grid(row=2, column=i, sticky="w", padx=3)
            self.key_labels[key] = lbl

    def _resize_perspectives(self, event) -> None:
        lines = 2 if event.height < 350 else 3
        for txt in self.view_text.values():
            if txt.cget("height") != lines:
                txt.configure(height=lines)

    def _build_inspector(self, parent) -> None:
        self.inspector = ttk.Notebook(parent)
        self.inspector.pack(fill="both", expand=True)
        self.inspector.enable_traversal()
        self.log_panel = self._card(self.inspector)
        self.result_panel = self._card(self.inspector)
        self.inspector.add(self.log_panel, text="事件日志")
        self.inspector.add(self.result_panel, text="结果判定")
        log_options = ttk.Frame(self.log_panel, style="Panel.TFrame", padding=(10, 5))
        log_options.pack(fill="x")
        ttk.Checkbutton(log_options, text="详细日志（含网络层）", variable=self.verbose_var,
                        command=self._render_log).pack(side="right")
        self.log_text = self._make_text(self.log_panel, empty="运行场景后，事件会显示在这里。")
        for kind, color in LOG_TAG_COLORS.items():
            self.log_text.tag_configure(kind, foreground=color)
        self.result_text = self._make_text(self.result_panel, empty="演示结束后生成判定。")
        self.result_text.tag_configure("good", foreground=GOOD, background=LANE_FILLS["Bob"],
                                       font=self.bold_font, spacing1=4, spacing3=4)
        self.result_text.tag_configure("bad", foreground=DANGER, background=LANE_FILLS["Evil"],
                                       font=self.bold_font, spacing1=4, spacing3=4)
        self.result_text.tag_configure("title", font=self.section_font, spacing3=6)

    def _make_text(self, parent, *, height=8, width=30, padding=12, empty="") -> tk.Text:
        frame = ttk.Frame(parent, style="Panel.TFrame")
        frame.pack(fill="both", expand=True)
        txt = tk.Text(frame, wrap="word", state="disabled", font=self.small_font, background=SURFACE,
                      foreground=INK, relief="flat", borderwidth=0, highlightthickness=0,
                      selectbackground="#dae5ff", selectforeground=INK, height=height, width=width,
                      padx=padding, pady=padding // 2, spacing2=2, spacing3=4)
        sb = ttk.Scrollbar(frame, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(side="left", fill="both", expand=True)
        if empty:
            label = tk.Label(txt, text=empty, background=SURFACE, foreground=MUTED, font=self.small_font)
            label.place(relx=0.5, rely=0.32, anchor="center")
            self.empty_labels[txt] = label
        return txt

    # ------------------------------------------------------------ 后台任务（queue + after）
    def _poll(self) -> None:
        self.runner.drain()
        self._poll_job = self.root.after(POLL_MS, self._poll)

    def close(self) -> None:
        """停止轮询与自动播放；窗口关闭前调用。"""
        self._cancel_autoplay()
        if self._poll_job is not None:
            self.root.after_cancel(self._poll_job)
            self._poll_job = None

    def _generate_keys(self) -> None:
        if self._keygen_pending:
            return
        self._cancel_autoplay()
        self._keygen_pending = True
        self._refresh_controls()
        self.phase_var.set("生成密钥")
        self.status_var.set(f"正在后台生成 {self.rsa_bits} 位 RSA 密钥（Alice/Bob/Evil 各一把）……")
        self.runner.submit(lambda: generate_keyring(self.rsa_bits), self._on_keys_ready, self._on_keygen_error)

    def _on_keys_ready(self, keyring: KeyRing) -> None:
        self._keygen_pending = False
        self.keyring = keyring
        self.reset()

    def _on_keygen_error(self, exc: BaseException) -> None:
        self._keygen_pending = False
        self.phase_var.set("生成失败")
        self._refresh_controls()
        self._report_task_error("生成 RSA 密钥", exc)

    def _on_comparison_error(self, exc: BaseException) -> None:
        self._comparison_pending = False
        self._refresh_controls()
        self._report_task_error("对比全部场景", exc)

    def _report_task_error(self, task: str, exc: BaseException) -> None:
        text = f"{task}失败：{exc}"
        self.status_var.set(text)
        messagebox.showerror("错误", text, parent=self.root)

    def compare_all(self) -> None:
        if self.keyring is None or self._keygen_pending or self._comparison_pending:
            return
        self._comparison_pending = True
        self._refresh_controls()
        self.status_var.set("正在后台运行全部场景……")
        keyring = self.keyring
        self.runner.submit(lambda: run_all(keyring), self._show_comparison, self._on_comparison_error)

    def _show_comparison(self, rows: list) -> None:
        self._comparison_pending = False
        self._refresh_controls()
        self.status_var.set("全部场景运行完成")
        win = tk.Toplevel(self.root)
        win.title("攻击与防御对比")
        win.configure(background=BG)
        win.geometry(f"{min(1000, self.root.winfo_width())}x480")
        win.minsize(660, 280)
        cols = ("scenario", "profile", "attack", "comm", "alerts")
        tree = ttk.Treeview(win, columns=cols, show="headings", selectmode="browse")
        for col, text, width in (("scenario", "场景", 330), ("profile", "防御配置", 250),
                                 ("attack", "攻击得逞", 90), ("comm", "正常通信", 90), ("alerts", "告警数", 70)):
            detail = col in ("scenario", "profile")
            tree.heading(col, text=text)
            tree.column(col, width=width, minwidth=135 if detail else width,
                        stretch=detail, anchor="w" if detail else "center")
        tree.tag_configure("bad", foreground=DANGER)
        tree.tag_configure("good", foreground=GOOD)
        tree.tag_configure("alternate", background="#f1f5fb")
        for i, (scenario, res) in enumerate(rows):
            tags = ("bad" if res.attack_succeeded else "good",) + (("alternate",) if i % 2 else ())
            tree.insert("", "end", tags=tags, values=(
                scenario.title, scenario.profile.describe(), "是" if res.attack_succeeded else "否",
                "是" if res.communication_ok else "否", len(res.alerts)))
        scroll = ttk.Scrollbar(win, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        win.columnconfigure(0, weight=1)
        win.rowconfigure(0, weight=1)
        tree.grid(row=0, column=0, sticky="nsew", padx=(12, 0), pady=12)
        scroll.grid(row=0, column=1, sticky="ns", padx=(0, 12), pady=12)

    def _refresh_controls(self) -> None:
        ready = self.world is not None and not self._keygen_pending
        available = {
            "keys": not self._keygen_pending,
            "compare": ready and not self._comparison_pending,
            "step": ready and not self._finished,
        }
        for key, b in self.buttons.items():
            b.state(["!disabled"] if available.get(key, ready) else ["disabled"])

    # ------------------------------------------------------------ 配置与世界
    def _on_scenario_selected(self) -> None:
        scenario = next((s for s in SCENARIOS if s.title == self.scenario_var.get()), None)
        if scenario is None:
            return
        self.auth_var.set(scenario.profile.auth_kex)
        self.mac_var.set(scenario.profile.mac)
        self.replay_var.set(scenario.profile.anti_replay)
        self.mode_var.set(MODE_LABELS[scenario.evil_mode])
        self.desc_label.configure(text=scenario.description)
        self.reset()

    def _on_config_changed(self) -> None:
        """用户手动改动防御开关或 Evil 行为后，视为自定义配置并重置。"""
        self.scenario_var.set(CUSTOM)
        self.desc_label.configure(text="自定义配置：按当前防御开关与 Evil 行为运行。")
        self.reset()

    def _current_mode(self) -> EvilMode:
        return next(m for m, label in MODE_LABELS.items() if label == self.mode_var.get())

    def _current_profile(self) -> SecurityProfile:
        return SecurityProfile("自定义", self.auth_var.get(), self.mac_var.get(), self.replay_var.get())

    def _tamper(self, text: str) -> str:
        """Evil 的篡改规则每次调用时读取输入框，运行中修改也会立即生效。"""
        old = self.tamper_old_var.get()
        return text.replace(old, self.tamper_new_var.get()) if old else text

    def _new_world(self) -> None:
        base = next((s for s in SCENARIOS if s.title == self.scenario_var.get()), SCENARIOS[0])
        self._messages = self.alice_text_var.get(), self.bob_text_var.get()
        script = (("Alice", "handshake", ""), ("Alice", "say", self._messages[0]),
                  ("Bob", "say", self._messages[1]))
        self.world = World(base, keyring=self.keyring, profile=self._current_profile(),
                           evil_mode=self._current_mode(), script=script)
        self.world.evil.tamper = self._tamper if self.world.evil.mode == EvilMode.MITM else None
        self.world.log.subscribe(self._on_event)

    def reset(self) -> None:
        """按当前配置重建世界并清空显示。"""
        if self.keyring is None or self._keygen_pending:
            return
        self._cancel_autoplay()
        self._new_world()
        self._finished = False
        self._ops.clear()
        self._follow_timeline = True
        self._evil_arrow_colors.clear()
        for txt in (self.log_text, self.result_text, *self.view_text.values()):
            self._clear_text(txt)
        self.inspector.select(self.log_panel)
        for lbl in self.key_labels.values():
            lbl.configure(text="—", foreground=MUTED)
        self._redraw()
        self._refresh_controls()
        self.phase_var.set("待运行")
        self.status_var.set(f"已就绪：{self.world.profile.describe()}；Evil：{MODE_LABELS[self.world.evil.mode]}")

    # ------------------------------------------------------------ 推进与播放
    def step(self) -> bool:
        """推进一步，返回是否还有后续步骤。"""
        if self.world is None or self._finished or self._keygen_pending:
            return False
        if self.world.steps == 0 and self._messages != (self.alice_text_var.get(), self.bob_text_var.get()):
            self._new_world()
        what = self.world.step()
        if what is None:
            self._finish()
            return False
        self.phase_var.set("进行中")
        self.status_var.set(what)
        return True

    def run_all_steps(self) -> None:
        if self.world is None or self._keygen_pending:
            return
        if self._finished:
            self.reset()
        else:
            self._cancel_autoplay()
        while self.step():
            pass
        self.inspector.select(self.result_panel)

    def toggle_autoplay(self) -> None:
        if self._autoplay_job is not None:
            self._cancel_autoplay()
            if not self._finished:
                self.phase_var.set("已暂停")
            return
        if self.world is None or self._keygen_pending:
            return
        if self._finished:
            self.reset()
        self.buttons["auto"].configure(text="暂停播放")
        self._autoplay_tick()

    def _autoplay_tick(self) -> None:
        self._autoplay_job = None
        if self.step():
            self._autoplay_job = self.root.after(AUTOPLAY_MS, self._autoplay_tick)

    def _cancel_autoplay(self) -> None:
        if self._autoplay_job is not None:
            self.root.after_cancel(self._autoplay_job)
            self._autoplay_job = None
        self.buttons["auto"].configure(text="自动播放")

    def evil_replay(self) -> None:
        """交互式攻击：随时让 Evil 把已记录的数据包重放给 Bob，之后用单步观察 Bob 的反应。"""
        if self.world is None or self._keygen_pending:
            return
        if not self.world.evil.replay(0):
            self.status_var.set("Evil 还没有记录到 Alice→Bob 的数据包，请先推进到 Alice 发送消息之后")
            return
        self._finished = False
        self._refresh_controls()

    def _finish(self) -> None:
        self._finished = True
        self._cancel_autoplay()
        result = self.world.analyze()
        sc = self.world.scenario
        t = self.result_text
        self.empty_labels[t].place_forget()
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", f"{'自定义配置' if self.scenario_var.get() == CUSTOM else sc.title}\n", "title")
        t.insert("end", f"防御配置：{self.world.profile.describe()}\n")
        t.insert("end", f"Evil 行为：{MODE_LABELS[self.world.evil.mode]}\n\n")
        t.insert("end", "攻击得逞 ✗\n" if result.attack_succeeded else "攻击未得逞 ✓\n",
                 "bad" if result.attack_succeeded else "good")
        t.insert("end", "双方正常通信完成 ✓\n" if result.communication_ok else "通信未完整完成\n",
                 "good" if result.communication_ok else "bad")
        t.insert("end", "\n")
        details = result.summary.rsplit("\n", 2)[:-2]  # 最后两行判定已经在上方显示。
        if details:
            t.insert("end", details[0] + "\n\n")
        t.insert("end", "收发消息\n", "title")
        t.insert("end", f"Alice 发出：{result.alice_sent}\nBob 收到：{result.bob_received}\n"
                        f"Bob 发出：{result.bob_sent}\nAlice 收到：{result.alice_received}\n")
        t.configure(state="disabled")
        t.yview_moveto(0)
        self._refresh_controls()
        self.phase_var.set("已完成")
        self.status_var.set("演示结束：" + ("攻击得逞" if result.attack_succeeded else "攻击未得逞"))

    # ------------------------------------------------------------ 事件显示
    def _on_event(self, e: ev.Event) -> None:
        self._append_log(e)
        k, actor = e.kind, e.actor
        if k == ev.NET:
            self._add_arrow(e)
        elif k == ev.FORWARD:
            self._evil_arrow_colors.append(NORMAL)
        elif k in (ev.MODIFY, ev.REPLAY) and actor == "Evil":
            color = DANGER if k == ev.MODIFY else WARN
            self._evil_arrow_colors.append(color)
            self._add_note("Evil", ("篡改：" if k == ev.MODIFY else "") + e.text, color)
            self._view_append("Evil", e.text, color)
        elif k == ev.SPY and "text" in e.data:
            self._add_note("Evil", "窃听：" + e.data["text"], WARN)
            self._view_append("Evil", "窃听到：" + e.data["text"], WARN)
        elif k == ev.KEY:
            self._add_note(actor, self._key_note(e), KEYC)
            self._update_key_labels(e)
            self._view_append(actor, e.text, KEYC)
        elif k == ev.ALERT and actor in LANES:
            self._add_note(actor, "告警：" + e.text, DANGER)
            self._view_append(actor, e.text, DANGER)
        elif k == ev.APP and actor in LANES:
            self._add_note(actor, e.text, GOOD)
            self._view_append(actor, e.text, GOOD)

    @staticmethod
    def _key_note(e: ev.Event) -> str:
        if e.actor != "Evil":
            return "会话密钥 " + e.data["fingerprint"]
        return "持有两把会话密钥" if "with_bob" in e.data else "与 Alice 建立会话"

    def _update_key_labels(self, e: ev.Event) -> None:
        if e.actor in ("Alice", "Bob"):
            self.key_labels[e.actor].configure(text=e.data["fingerprint"])
        else:
            if "with_alice" in e.data:
                self.key_labels["Evil↔Alice"].configure(text=e.data["with_alice"])
            if "with_bob" in e.data:
                self.key_labels["Evil↔Bob"].configure(text=e.data["with_bob"])
        a, b = (self.key_labels[k].cget("text") for k in ("Alice", "Bob"))
        if a != "—" and b != "—":
            color = GOOD if a == b else DANGER
            self.key_labels["Alice"].configure(foreground=color)
            self.key_labels["Bob"].configure(foreground=color)
        for k in ("Evil↔Alice", "Evil↔Bob"):
            if self.key_labels[k].cget("text") != "—":
                self.key_labels[k].configure(foreground=DANGER)

    def _append_log(self, e: ev.Event) -> None:
        if not self.verbose_var.get() and e.kind in (ev.NET, ev.RECV):
            return
        txt = self.log_text
        self.empty_labels[txt].place_forget()
        txt.configure(state="normal")
        txt.insert("end", ev.format_event(e) + "\n", e.kind)
        txt.configure(state="disabled")
        txt.see("end")

    def _render_log(self) -> None:
        self._clear_text(self.log_text)
        if self.world is not None:
            for e in self.world.log.events:
                self._append_log(e)

    def _view_append(self, who: str, text: str, color: str) -> None:
        txt = self.view_text[who]
        tag = f"c{color}"
        txt.tag_configure(tag, foreground=color)
        txt.configure(state="normal")
        txt.insert("end", text + "\n", tag)
        txt.configure(state="disabled")
        txt.see("end")

    def _clear_text(self, txt: tk.Text) -> None:
        txt.configure(state="normal")
        txt.delete("1.0", "end")
        txt.configure(state="disabled")
        if txt in self.empty_labels:
            self.empty_labels[txt].place(relx=0.5, rely=0.32, anchor="center")

    # ------------------------------------------------------------ 泳道图
    def _add_arrow(self, e: ev.Event) -> None:
        src, hop, dst = e.data["src"], e.data["hop"], e.data["dst"]
        try:
            msg = decode(e.data["wire"])
            label = f"{msg.type} ({msg.sender}→{msg.receiver})"
        except WireError:
            label = "无法解析的数据"
        if hop != dst:
            label += f" 经 {hop} 转发"
        color = self._evil_arrow_colors.popleft() if src == "Evil" and self._evil_arrow_colors else NORMAL
        self._ops.append(("arrow", src, hop, label, color))
        self._redraw()

    def _add_note(self, lane: str, text: str, color: str) -> None:
        self._ops.append(("note", lane, text, color))
        self._redraw()

    def _scroll_timeline(self, *args) -> None:
        self.canvas.yview(*args)
        self._follow_timeline = self.canvas.yview()[1] >= 0.999

    def _wheel_timeline(self, event) -> None:
        if event.delta:
            clicks = int(event.delta / 120) or (1 if event.delta > 0 else -1)
            self._scroll_timeline("scroll", -clicks * 2, "units")

    def _fit_timeline_label(self, text: str, limit: int) -> str:
        text = " ".join(text.splitlines())
        if self.small_font.measure(text) <= limit:
            return text
        ellipsis_width = self.small_font.measure("…")
        if ellipsis_width > limit:
            return ""
        # 二分查找能在当前泳道宽度内显示的最长前缀。
        lo, hi = 0, len(text)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.small_font.measure(text[:mid]) + ellipsis_width <= limit:
                lo = mid
            else:
                hi = mid - 1
        return text[:lo].rstrip() + "…"

    def _redraw(self) -> None:
        c = self.canvas
        offset = c.canvasy(0)
        c.delete("all")
        width = max(c.winfo_width(), 1)
        lane_width = width / len(LANES)
        xs = {name: (i + 0.5) * lane_width for i, name in enumerate(LANES)}
        bottom = max(TOP_Y + ROW_H * len(self._ops), c.winfo_height())
        # 泳道标题画在独立的固定画布里，内容滚动时标题始终可见
        self.header.delete("all")
        for name, x in xs.items():
            start_x, end_x = x - lane_width / 2, x + lane_width / 2
            self.header.create_rectangle(start_x + 2, 2, end_x - 2, 34, fill=LANE_FILLS[name], outline="")
            self.header.create_text(x, 18, text=name, fill=LANE_COLORS[name], font=self.bold_font)
            c.create_rectangle(start_x + 2, 0, end_x - 2, bottom, fill=LANE_FILLS[name], outline="")
            c.create_line(x, 0, x, bottom, fill="#b5c3d7", dash=(3, 5))
        if not self._ops:
            self._timeline_label(width / 2, bottom / 2, "单步或运行场景后查看通信时序", MUTED, SURFACE, width - 16)
        for i, op in enumerate(self._ops):
            y = TOP_Y + i * ROW_H
            if op[0] == "arrow":
                _, src, hop, label, color = op
                x1, x2 = xs[src], xs[hop]
                c.create_line(x1, y + 5, x2, y + 5, arrow=tk.LAST, fill=color, width=2)
                c.create_oval(x1 - 3, y + 2, x1 + 3, y + 8, fill=color, outline="")
                self._timeline_label((x1 + x2) / 2, y - 8, label, color, SURFACE, abs(x1 - x2) - 14)
            else:
                _, lane, text, color = op
                self._timeline_label(xs[lane], y, text, color, NOTE_FILLS.get(color, SURFACE), lane_width - 20)
        c.configure(scrollregion=(0, 0, width, bottom))
        c.yview_moveto(1.0 if self._follow_timeline else offset / bottom)

    def _timeline_label(self, x, y, text, color, fill, width) -> None:
        c = self.canvas
        label = self._fit_timeline_label(text, width)
        item = c.create_text(x, y, text=label, fill=color, font=self.small_font)
        x1, y1, x2, y2 = c.bbox(item)
        box = c.create_rectangle(x1 - 5, y1 - 2, x2 + 5, y2 + 2, fill=fill, outline="")
        c.tag_lower(box, item)


def main(rsa_bits: int = 2048) -> int:
    """启动图形界面。"""
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"无法启动图形界面（{exc}）。可使用 python -m mitmlab run normal。", file=sys.stderr)
        return 1
    app = App(root, rsa_bits=rsa_bits)

    def on_close() -> None:
        app.close()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()
    return 0
