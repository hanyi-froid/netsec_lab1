"""tkinter 图形界面：选择场景、观察三方通信过程、对比攻击与防御结果。

界面构成：
  * 顶部：场景选择、防御开关、Evil 行为、消息与篡改规则、操作按钮
  * 左侧：Alice | Evil | Bob 三泳道时序图（箭头=线路上的报文，方框=各方的关键行为）
          其下为三方"视角"——各自实际看到/收到的内容，以及各方持有的会话密钥指纹
  * 右侧：事件日志与结果判定

线程安全：世界（World）的推进都在主线程完成（速度很快）；RSA 密钥生成与"对比全部场景"
这类耗时任务在工作线程里运行，结果经 queue.Queue 返回，由 root.after() 轮询并在主线程更新界面。
"""

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
LANE_COLORS = {"Alice": "#2f6fba", "Evil": "#c0392b", "Bob": "#27885a"}
NORMAL, DANGER, WARN, GOOD, MUTED, KEYC = "#34495e", "#c0392b", "#d68910", "#1e8449", "#7f8c8d", "#7d3c98"
ROW_H, TOP_Y = 34, 24
POLL_MS = 50
AUTOPLAY_MS = 450
FONT_CANDIDATES = ("Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC",
                   "WenQuanYi Micro Hei", "SimHei")
LOG_TAG_COLORS = {ev.ALERT: DANGER, ev.MODIFY: DANGER, ev.REPLAY: WARN, ev.SPY: WARN, ev.KEY: KEYC,
                  ev.APP: GOOD, ev.INTERCEPT: "#a04000", ev.FORWARD: MUTED, ev.NET: MUTED,
                  ev.RECV: MUTED, ev.FAULT: WARN}
CUSTOM = "（自定义配置）"


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit - 1] + "…"


class App:
    def __init__(self, root: tk.Tk, rsa_bits: int = 2048, keyring: KeyRing = None):
        self.root, self.rsa_bits, self.keyring = root, rsa_bits, keyring
        self.runner = BackgroundRunner()
        self.world = None
        self._autoplay_job = None
        self._finished = False
        self._ops: list = []                # 泳道图绘制指令
        self._evil_arrow_colors: deque = deque()
        self._keygen_pending = False
        self._poll_job = None
        self._setup_fonts()
        self._build_ui()
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
            for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont", "TkFixedFont"):
                tkfont.nametofont(name).configure(family=family)
        self.font_family = family or tkfont.nametofont("TkDefaultFont").actual("family")
        self.small_font = (self.font_family, 9)
        self.bold_font = (self.font_family, 10, "bold")

    def _build_ui(self) -> None:
        r = self.root
        r.title("中间人攻击与防御实验器")
        # 窗口尺寸随屏幕自适应（高 DPI 缩放下 tkinter 的像素数会被放大）
        w = min(1360, r.winfo_screenwidth() - 60)
        h = min(860, r.winfo_screenheight() - 100)
        r.geometry(f"{w}x{h}+20+20")
        r.minsize(min(1000, w), min(640, h))

        self.scenario_var = tk.StringVar()
        self.auth_var, self.mac_var, self.replay_var = tk.BooleanVar(), tk.BooleanVar(), tk.BooleanVar()
        self.mode_var = tk.StringVar()
        self.alice_text_var = tk.StringVar(value=ALICE_TEXT)
        self.bob_text_var = tk.StringVar(value=BOB_TEXT)
        self.tamper_old_var, self.tamper_new_var = tk.StringVar(value="100"), tk.StringVar(value="10000")
        self.verbose_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="就绪")

        top = ttk.LabelFrame(r, text="场景与配置", padding=6)
        top.pack(fill="x", padx=8, pady=(8, 4))
        ttk.Label(top, text="场景").grid(row=0, column=0, sticky="w")
        self.scenario_box = ttk.Combobox(top, textvariable=self.scenario_var, state="readonly", width=44,
                                         values=[s.title for s in SCENARIOS])
        self.scenario_box.grid(row=0, column=1, columnspan=3, sticky="w", padx=4)
        self.scenario_box.bind("<<ComboboxSelected>>", lambda _e: self._on_scenario_selected())
        self.desc_label = ttk.Label(top, text="", wraplength=760, foreground=MUTED)
        self.desc_label.grid(row=0, column=4, columnspan=6, sticky="w", padx=8)

        ttk.Label(top, text="防御").grid(row=1, column=0, sticky="w", pady=(6, 0))
        for i, (text, var) in enumerate((("签名认证 DH", self.auth_var), ("HMAC 完整性", self.mac_var),
                                         ("序号防重放", self.replay_var))):
            ttk.Checkbutton(top, text=text, variable=var, command=self._on_config_changed).grid(
                row=1, column=1 + i, sticky="w", padx=4, pady=(6, 0))
        ttk.Label(top, text="Evil 行为").grid(row=1, column=4, sticky="e", pady=(6, 0))
        self.mode_box = ttk.Combobox(top, textvariable=self.mode_var, state="readonly", width=26,
                                     values=list(MODE_LABELS.values()))
        self.mode_box.grid(row=1, column=5, columnspan=2, sticky="w", padx=4, pady=(6, 0))
        self.mode_box.bind("<<ComboboxSelected>>", lambda _e: self._on_config_changed())

        ttk.Label(top, text="Alice 说").grid(row=2, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(top, textvariable=self.alice_text_var, width=34).grid(row=2, column=1, columnspan=3,
                                                                       sticky="we", padx=4, pady=(6, 0))
        ttk.Label(top, text="Bob 回复").grid(row=2, column=4, sticky="e", pady=(6, 0))
        ttk.Entry(top, textvariable=self.bob_text_var, width=28).grid(row=2, column=5, columnspan=2,
                                                                     sticky="w", padx=4, pady=(6, 0))
        ttk.Label(top, text="Evil 篡改：把").grid(row=2, column=7, sticky="e", pady=(6, 0))
        ttk.Entry(top, textvariable=self.tamper_old_var, width=8).grid(row=2, column=8, padx=2, pady=(6, 0))
        ttk.Label(top, text="改成").grid(row=2, column=9, pady=(6, 0))
        ttk.Entry(top, textvariable=self.tamper_new_var, width=10).grid(row=2, column=10, padx=2, pady=(6, 0))

        bar = ttk.Frame(r)
        bar.pack(fill="x", padx=8, pady=4)
        self.buttons = {}
        for key, text, cmd in (("reset", "重置", self.reset), ("step", "单步 ▶", self.step),
                               ("auto", "自动播放", self.toggle_autoplay), ("run", "一键运行 ⏩", self.run_all_steps),
                               ("replay", "Evil 立即重放", self.evil_replay),
                               ("compare", "对比全部场景", self.compare_all),
                               ("keys", "重新生成 RSA 密钥", self._generate_keys)):
            b = ttk.Button(bar, text=text, command=cmd)
            b.pack(side="left", padx=3)
            self.buttons[key] = b
        ttk.Checkbutton(bar, text="详细日志（含网络层）", variable=self.verbose_var,
                        command=self._render_log).pack(side="left", padx=12)

        paned = ttk.PanedWindow(r, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=8, pady=4)
        left = ttk.Frame(paned)
        right = ttk.Frame(paned)
        paned.add(left, weight=3)
        paned.add(right, weight=2)

        # 泳道图
        lane_frame = ttk.LabelFrame(left, text="通信过程（时间自上而下）", padding=2)
        lane_frame.pack(fill="both", expand=True)
        self.header = tk.Canvas(lane_frame, background="white", highlightthickness=0, height=44)
        self.header.pack(side="top", fill="x")
        self.canvas = tk.Canvas(lane_frame, background="white", highlightthickness=0, height=340)
        vbar = ttk.Scrollbar(lane_frame, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=vbar.set)
        vbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.canvas.bind("<Configure>", lambda _e: self._redraw())

        # 三方视角
        views = ttk.Frame(left)
        views.pack(fill="x", pady=(4, 0))
        self.view_text, self.key_labels = {}, {}
        for i, who in enumerate(LANES):
            col = ttk.LabelFrame(views, text=f"{who} 的视角", padding=3)
            col.grid(row=0, column=i, sticky="nsew", padx=2)
            views.columnconfigure(i, weight=1)
            txt = tk.Text(col, height=7, width=30, wrap="word", state="disabled", font=self.small_font,
                          foreground=LANE_COLORS[who], relief="flat", background="#fafafa")
            txt.pack(fill="both", expand=True)
            self.view_text[who] = txt
        keys = ttk.LabelFrame(left, text="各方持有的会话密钥指纹（一致才表示真的在和对方通信）", padding=4)
        keys.pack(fill="x", pady=(4, 0))
        for i, (key, label) in enumerate((("Alice", "Alice"), ("Evil↔Alice", "Evil 与 Alice"),
                                          ("Evil↔Bob", "Evil 与 Bob"), ("Bob", "Bob"))):
            ttk.Label(keys, text=label + "：").grid(row=0, column=2 * i, sticky="e")
            lbl = ttk.Label(keys, text="—", font=(self.font_family, 10, "bold"), width=14)
            lbl.grid(row=0, column=2 * i + 1, sticky="w", padx=(0, 10))
            self.key_labels[key] = lbl

        # 日志与结果
        notebook = ttk.Notebook(right)
        notebook.pack(fill="both", expand=True)
        self.log_text = self._make_text(notebook, "事件日志")
        for kind, color in LOG_TAG_COLORS.items():
            self.log_text.tag_configure(kind, foreground=color)
        self.result_text = self._make_text(notebook, "结果判定")
        self.result_text.tag_configure("good", foreground=GOOD, font=self.bold_font)
        self.result_text.tag_configure("bad", foreground=DANGER, font=self.bold_font)
        self.result_text.tag_configure("title", font=self.bold_font)

        ttk.Label(r, textvariable=self.status_var, relief="sunken", anchor="w", padding=(6, 2)).pack(
            fill="x", side="bottom")

    def _make_text(self, notebook: ttk.Notebook, title: str) -> tk.Text:
        frame = ttk.Frame(notebook)
        txt = tk.Text(frame, wrap="word", state="disabled", font=self.small_font, background="#fcfcfc")
        sb = ttk.Scrollbar(frame, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(side="left", fill="both", expand=True)
        notebook.add(frame, text=title)
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
        self._keygen_pending = True
        self._set_controls(False)
        self.status_var.set(f"正在后台生成 {self.rsa_bits} 位 RSA 密钥（Alice/Bob/Evil 各一把）……")
        self.runner.submit(lambda: generate_keyring(self.rsa_bits), self._on_keys_ready, self._on_task_error)

    def _on_keys_ready(self, keyring: KeyRing) -> None:
        self._keygen_pending = False
        self.keyring = keyring
        self._set_controls(True)
        self.status_var.set("RSA 密钥就绪，请选择场景")
        if not self.scenario_var.get():
            self.scenario_var.set(SCENARIOS[0].title)
            self._on_scenario_selected()
        else:
            self.reset()

    def _on_task_error(self, exc: BaseException) -> None:
        self._keygen_pending = False
        self._set_controls(self.keyring is not None)
        self.status_var.set(f"后台任务失败：{exc}")
        messagebox.showerror("错误", f"后台任务失败：{exc}")

    def compare_all(self) -> None:
        if self.keyring is None:
            return
        self.buttons["compare"].state(["disabled"])
        self.status_var.set("正在后台运行全部场景……")
        keyring = self.keyring
        self.runner.submit(lambda: run_all(keyring), self._show_comparison, self._on_task_error)

    def _show_comparison(self, rows: list) -> None:
        self.buttons["compare"].state(["!disabled"])
        self.status_var.set("全部场景运行完成")
        win = tk.Toplevel(self.root)
        win.title("攻击与防御对比")
        win.geometry("1000x430")
        cols = ("scenario", "profile", "attack", "comm", "alerts")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        for col, text, width in (("scenario", "场景", 330), ("profile", "防御配置", 250),
                                 ("attack", "攻击得逞", 80), ("comm", "正常通信", 80), ("alerts", "告警数", 60)):
            tree.heading(col, text=text)
            tree.column(col, width=width, anchor="w")
        tree.tag_configure("bad", foreground=DANGER)
        tree.tag_configure("good", foreground=GOOD)
        for scenario, res in rows:
            tree.insert("", "end", tags=("bad" if res.attack_succeeded else "good",), values=(
                scenario.title, scenario.profile.describe(), "是" if res.attack_succeeded else "否",
                "是" if res.communication_ok else "否", len(res.alerts)))
        tree.pack(fill="both", expand=True, padx=6, pady=6)

    def _set_controls(self, enabled: bool) -> None:
        for key, b in self.buttons.items():
            if key == "keys":
                b.state(["!disabled"] if not self._keygen_pending else ["disabled"])
            else:
                b.state(["!disabled"] if enabled else ["disabled"])

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

    def reset(self) -> None:
        """按当前配置重建世界并清空显示。"""
        if self.keyring is None:
            return
        self._cancel_autoplay()
        base = next((s for s in SCENARIOS if s.title == self.scenario_var.get()), SCENARIOS[0])
        script = (("Alice", "handshake", ""), ("Alice", "say", self.alice_text_var.get()),
                  ("Bob", "say", self.bob_text_var.get()))
        mode = self._current_mode()
        self.world = World(base, keyring=self.keyring, profile=self._current_profile(), evil_mode=mode,
                           script=script)
        self.world.evil.tamper = self._tamper if mode == EvilMode.MITM else None
        self.world.log.subscribe(self._on_event)
        self._finished = False
        self._ops.clear()
        self._evil_arrow_colors.clear()
        for txt in (self.log_text, self.result_text, *self.view_text.values()):
            self._set_text(txt, "")
        for lbl in self.key_labels.values():
            lbl.configure(text="—", foreground="black")
        self._redraw()
        self._set_controls(True)
        self.status_var.set(f"已就绪：{self._current_profile().describe()}；Evil：{MODE_LABELS[mode]}")

    # ------------------------------------------------------------ 推进与播放
    def step(self) -> bool:
        """推进一步，返回是否还有后续步骤。"""
        if self.world is None or self._finished:
            return False
        what = self.world.step()
        if what is None:
            self._finish()
            return False
        self.status_var.set(what)
        return True

    def run_all_steps(self) -> None:
        self._cancel_autoplay()
        while self.step():
            pass

    def toggle_autoplay(self) -> None:
        if self._autoplay_job is not None:
            self._cancel_autoplay()
            return
        self.buttons["auto"].configure(text="暂停播放")
        self._autoplay_tick()

    def _autoplay_tick(self) -> None:
        if self.step():
            self._autoplay_job = self.root.after(AUTOPLAY_MS, self._autoplay_tick)
        else:
            self._cancel_autoplay()

    def _cancel_autoplay(self) -> None:
        if self._autoplay_job is not None:
            self.root.after_cancel(self._autoplay_job)
            self._autoplay_job = None
        self.buttons["auto"].configure(text="自动播放")

    def evil_replay(self) -> None:
        """交互式攻击：随时让 Evil 把已记录的数据包重放给 Bob，之后用单步观察 Bob 的反应。"""
        if self.world is None:
            return
        self._finished = False
        if not self.world.evil.replay(0):
            self.status_var.set("Evil 还没有记录到 Alice→Bob 的数据包，请先推进到 Alice 发送消息之后")

    def _finish(self) -> None:
        self._finished = True
        result = self.world.analyze()
        sc = self.world.scenario
        t = self.result_text
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", f"{'自定义配置' if self.scenario_var.get() == CUSTOM else sc.title}\n", "title")
        t.insert("end", f"防御配置：{self.world.profile.describe()}\n")
        t.insert("end", f"Evil 行为：{MODE_LABELS[self.world.evil.mode]}\n\n")
        t.insert("end", "攻击得逞 ✗\n" if result.attack_succeeded else "攻击未得逞 ✓\n",
                 "bad" if result.attack_succeeded else "good")
        t.insert("end", "双方正常通信完成 ✓\n\n" if result.communication_ok else "通信未完整完成\n\n",
                 "good" if result.communication_ok else "bad")
        t.insert("end", result.summary + "\n\n")
        t.insert("end", f"Alice 发出：{result.alice_sent}\nBob 收到：{result.bob_received}\n"
                        f"Bob 发出：{result.bob_sent}\nAlice 收到：{result.alice_received}\n")
        t.configure(state="disabled")
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
        txt.configure(state="normal")
        txt.insert("end", ev.format_event(e) + "\n", e.kind)
        txt.configure(state="disabled")
        txt.see("end")

    def _render_log(self) -> None:
        self._set_text(self.log_text, "")
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

    @staticmethod
    def _set_text(txt: tk.Text, content: str) -> None:
        txt.configure(state="normal")
        txt.delete("1.0", "end")
        txt.insert("end", content)
        txt.configure(state="disabled")

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
        self._ops.append(("note", lane, _clip(text, 24), color))
        self._redraw()

    def _redraw(self) -> None:
        c = self.canvas
        c.delete("all")
        width = max(c.winfo_width(), 640)
        xs = {name: int(width * (2 * i + 1) / 6) for i, name in enumerate(LANES)}
        bottom = max(TOP_Y + ROW_H * (len(self._ops) + 1), c.winfo_height())
        # 泳道标题画在独立的固定画布里，内容滚动时标题始终可见
        self.header.delete("all")
        for name, x in xs.items():
            self.header.create_rectangle(x - 46, 8, x + 46, 38, fill=LANE_COLORS[name], outline="")
            self.header.create_text(x, 23, text=name, fill="white", font=self.bold_font)
            c.create_line(x, 0, x, bottom, fill="#cccccc", dash=(4, 4))
        for i, op in enumerate(self._ops):
            y = TOP_Y + i * ROW_H
            if op[0] == "arrow":
                _, src, hop, label, color = op
                x1, x2 = xs[src], xs[hop]
                c.create_line(x1, y, x2, y, arrow=tk.LAST, fill=color, width=2)
                c.create_text((x1 + x2) / 2, y - 10, text=_clip(label, 52), fill=color, font=self.small_font)
            else:
                _, lane, text, color = op
                item = c.create_text(xs[lane], y, text=text, fill=color, font=self.small_font)
                x1, y1, x2, y2 = c.bbox(item)
                box = c.create_rectangle(x1 - 4, y1 - 2, x2 + 4, y2 + 2, fill="white", outline=color)
                c.tag_raise(item, box)
        c.configure(scrollregion=(0, 0, width, bottom))
        c.yview_moveto(1.0)


def main(rsa_bits: int = 2048) -> int:
    """启动图形界面。"""
    root = tk.Tk()
    app = App(root, rsa_bits=rsa_bits)

    def on_close() -> None:
        app.close()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()
    return 0
