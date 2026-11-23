"""GUI 测试：后台任务执行器（无需显示环境）与 tkinter 界面的行为测试（无显示环境时自动跳过）。"""

import ast
import gc
import pathlib
import threading
import time
import unittest
from unittest.mock import patch

try:
    import tkinter as tk
except ModuleNotFoundError as exc:
    if exc.name not in {"tkinter", "_tkinter"}:
        raise
    tk = None

from mitmlab.gui.worker import BackgroundRunner
from mitmlab.proto.identities import generate_keyring
from mitmlab.proto.scenarios import ALICE_TEXT, SCENARIO_BY_ID

KEYRING = generate_keyring(1024)


class BackgroundRunnerTests(unittest.TestCase):
    def _wait(self, runner, cond, timeout=10):
        end = time.time() + timeout
        while not cond() and time.time() < end:
            runner.drain()
            time.sleep(0.005)

    def test_work_runs_in_worker_and_callback_in_draining_thread(self):
        runner, seen = BackgroundRunner(), {}

        def work():
            seen["work"] = threading.get_ident()
            return 42

        runner.submit(work, lambda r: seen.update(cb=threading.get_ident(), result=r))
        self._wait(runner, lambda: "result" in seen)
        self.assertEqual(seen["result"], 42)
        self.assertNotEqual(seen["work"], threading.get_ident())
        self.assertEqual(seen["cb"], threading.get_ident())  # 回调在调用 drain 的（主）线程执行

    def test_callback_never_runs_before_drain(self):
        runner, hits = BackgroundRunner(), []
        runner.submit(lambda: 1, hits.append).join()
        self.assertEqual(hits, [])
        self.assertEqual(runner.drain(), 1)
        self.assertEqual(hits, [1])
        self.assertEqual(runner.drain(), 0)

    def test_errors_are_delivered_to_error_callback(self):
        runner, errors = BackgroundRunner(), []

        def boom():
            raise ValueError("bad")

        runner.submit(boom, lambda r: None, errors.append).join()
        runner.drain()
        self.assertIsInstance(errors[0], ValueError)

    def test_unhandled_error_is_raised_in_main_thread(self):
        runner = BackgroundRunner()
        runner.submit(lambda: 1 / 0, lambda r: None).join()
        with self.assertRaises(ZeroDivisionError):
            runner.drain()


class GuiSourceRuleTests(unittest.TestCase):
    def test_app_module_does_not_use_threads_directly(self):
        # 线程只允许出现在 worker.py，界面代码只通过 BackgroundRunner + after 轮询交互
        tree = ast.parse(pathlib.Path("mitmlab/gui/app.py").read_text(encoding="utf-8"))
        imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        imported |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        self.assertNotIn("threading", imported)
        self.assertIn("BackgroundRunner", pathlib.Path("mitmlab/gui/app.py").read_text(encoding="utf-8"))


_ROOT = None


def _shared_root():
    """整个测试模块共用一个 Tk 根窗口：反复创建/销毁 Tk 解释器在 Windows 上偶发初始化失败。"""
    global _ROOT
    if tk is None:
        raise unittest.SkipTest("当前 Python 未安装 tkinter")
    if _ROOT is None:
        try:
            _ROOT = tk.Tk()
        except tk.TclError as exc:  # 无图形显示环境
            raise unittest.SkipTest(f"无法创建 Tk 窗口: {exc}")
        _ROOT.withdraw()
    return _ROOT


def _make_app(testcase, **kwargs):
    """创建 App，并在测试结束时关闭它、清理根窗口下的所有控件。"""
    root = _shared_root()
    from mitmlab.gui.app import App

    def cleanup():
        app.close()
        for child in root.winfo_children():
            child.destroy()
        gc.collect()  # 在主线程回收 tk 变量，避免被工作线程的 GC 触发 Tcl 调用

    app = App(root, **kwargs)
    testcase.addCleanup(cleanup)
    return app


class GuiTests(unittest.TestCase):
    def setUp(self):
        self.app = _make_app(self, keyring=KEYRING)
        self.root = self.app.root

    def select(self, sid):
        self.app.scenario_var.set(SCENARIO_BY_ID[sid].title)
        self.app._on_scenario_selected()

    @staticmethod
    def text_of(widget):
        return widget.get("1.0", "end")

    def test_initial_state_loaded_first_scenario(self):
        self.assertEqual(self.app.scenario_var.get(), SCENARIO_BY_ID["normal"].title)
        self.assertIsNotNone(self.app.world)

    def test_run_button_shows_result_and_runs_again_with_updated_message(self):
        self.select("normal")
        self.app.buttons["run"].invoke()
        first_world = self.app.world
        self.assertTrue(self.app._finished)
        self.assertEqual(self.app.inspector.select(), str(self.app.result_panel))
        self.assertIn(ALICE_TEXT, self.text_of(self.app.result_text))

        self.app.inspector.select(self.app.log_panel)
        self.app.alice_text_var.set("第二次运行的消息")
        self.app.buttons["run"].invoke()
        self.assertIsNot(self.app.world, first_world)
        self.assertEqual(self.app.world.bob.received, ["第二次运行的消息"])
        self.assertEqual(self.app.inspector.select(), str(self.app.result_panel))
        self.assertNotIn(ALICE_TEXT, self.text_of(self.app.result_text))
        self.assertIn("第二次运行的消息", self.text_of(self.app.result_text))

    def test_mitm_run_shows_attack_in_every_panel(self):
        self.select("mitm")
        self.app.run_all_steps()
        self.assertIn("窃听", self.text_of(self.app.log_text))
        self.assertIn("攻击得逞", self.text_of(self.app.result_text))
        self.assertIn("10000", self.text_of(self.app.view_text["Bob"]))
        self.assertIn("窃听到", self.text_of(self.app.view_text["Evil"]))
        self.assertNotEqual(self.app.key_labels["Alice"].cget("text"), self.app.key_labels["Bob"].cget("text"))
        self.assertEqual(self.app.key_labels["Evil↔Alice"].cget("text"), self.app.key_labels["Alice"].cget("text"))
        self.assertGreater(len(self.app.canvas.find_all()), 20)

    def test_defense_shows_alert_and_no_spying(self):
        self.select("defended-mitm")
        self.app.run_all_steps()
        self.assertIn("签名验证失败", self.text_of(self.app.log_text))
        self.assertIn("攻击未得逞", self.text_of(self.app.result_text))
        self.assertNotIn("窃听到", self.text_of(self.app.view_text["Evil"]))  # Evil 试图替换密钥，但读不到任何明文

    def test_bitflip_displays_invalid_utf8_as_escaped_bytes(self):
        self.select("bitflip")
        self.app.run_all_steps()
        bob_view = self.text_of(self.app.view_text["Bob"])
        result_view = self.text_of(self.app.result_text)
        self.assertIn("[非 UTF-8 数据，非法字节已转义]", bob_view)
        self.assertIn(r"\x", bob_view)
        self.assertNotIn("\ufffd", bob_view + result_view)

    def test_normal_keys_match(self):
        self.select("defended-normal")
        self.app.run_all_steps()
        self.assertEqual(self.app.key_labels["Alice"].cget("text"), self.app.key_labels["Bob"].cget("text"))
        self.assertEqual(self.app.key_labels["Evil↔Alice"].cget("text"), "—")
        self.assertIn(ALICE_TEXT, self.text_of(self.app.view_text["Bob"]))

    def test_messages_are_read_when_the_demo_starts(self):
        self.select("defended-normal")
        self.app.alice_text_var.set("新的 Alice 消息")
        self.app.bob_text_var.set("新的 Bob 回复")
        self.assertTrue(self.app.step())
        self.app.alice_text_var.set("下次演示使用")
        self.app.buttons["run"].invoke()

        self.assertEqual(self.app.world.bob.received, ["新的 Alice 消息"])
        self.assertEqual(self.app.world.alice.received, ["新的 Bob 回复"])

    def test_single_step_advances_one_action_at_a_time(self):
        self.select("normal")
        before = len(self.app.world.log.events)
        self.assertTrue(self.app.step())
        self.assertGreater(len(self.app.world.log.events), before)
        self.assertFalse(self.app._finished)
        while self.app.step():
            pass
        self.assertTrue(self.app._finished)
        self.assertFalse(self.app.step())

    def test_reset_clears_everything(self):
        self.select("mitm")
        self.app.run_all_steps()
        self.app.reset()
        self.assertEqual(self.text_of(self.app.log_text).strip(), "")
        self.assertEqual(self.text_of(self.app.result_text).strip(), "")
        self.assertEqual(self.app.key_labels["Alice"].cget("text"), "—")
        self.assertEqual(len(self.app._ops), 0)

    def test_custom_configuration(self):
        self.select("normal")
        self.app.mode_var.set("DH 密钥替换（窃听 + 篡改）")
        self.app.mode_box.event_generate("<<ComboboxSelected>>")
        self.root.update()
        self.assertIn("自定义", self.app.scenario_var.get())
        self.app.tamper_new_var.set("999")
        self.app.run_all_steps()
        self.assertIn("999", self.text_of(self.app.view_text["Bob"]))
        self.app.auth_var.set(True)
        self.app._on_config_changed()
        self.app.run_all_steps()
        self.assertIn("攻击未得逞", self.text_of(self.app.result_text))

    def test_manual_evil_replay(self):
        self.select("normal")
        self.app.run_all_steps()
        self.app.evil_replay()
        self.app.run_all_steps()
        self.assertEqual(self.app.world.bob.received.count(ALICE_TEXT), 2)

    def test_replay_before_any_traffic_only_reports(self):
        self.select("normal")
        self.app.evil_replay()
        self.assertIn("还没有记录", self.app.status_var.get())

    def test_verbose_log_toggle(self):
        self.select("normal")
        self.app.run_all_steps()
        self.assertNotIn("网络", self.text_of(self.app.log_text))
        self.app.verbose_var.set(True)
        self.app._render_log()
        self.assertIn("网络", self.text_of(self.app.log_text))

    def test_autoplay_runs_to_completion(self):
        from mitmlab.gui import app as app_module
        self.app.buttons["run"].invoke()
        previous_world = self.app.world
        self.assertTrue(self.app.buttons["step"].instate(["disabled"]))
        auto = self.app.buttons["auto"]
        with patch.object(app_module, "AUTOPLAY_MS", 1):
            auto.invoke()
            self.assertIsNot(self.app.world, previous_world)
            auto.invoke()
            self.assertIsNone(self.app._autoplay_job)
            self.assertEqual(self.app.phase_var.get(), "已暂停")
            paused_world = self.app.world
            auto.invoke()
            self.assertIs(self.app.world, paused_world)
            end = time.time() + 20
            while not self.app._finished and time.time() < end:
                self.root.update()
                time.sleep(0.002)
        self.assertTrue(self.app._finished)
        self.assertEqual(auto.cget("text"), "自动播放")

    def test_comparison_failure_does_not_interrupt_key_generation(self):
        buttons = self.app.buttons
        with patch.object(self.app.runner, "submit") as submit:
            buttons["compare"].invoke()
            comparison_error = submit.call_args.args[2]
            buttons["reset"].invoke()
            self.assertTrue(buttons["compare"].instate(["disabled"]))
            buttons["compare"].invoke()
            self.assertEqual(submit.call_count, 1)

            buttons["auto"].invoke()
            self.assertIsNotNone(self.app._autoplay_job)
            buttons["keys"].invoke()
            self.assertIsNone(self.app._autoplay_job)
            self.assertTrue(buttons["run"].instate(["disabled"]))
            self.assertTrue(buttons["keys"].instate(["disabled"]))
            keys_ready = submit.call_args.args[1]
            with patch("mitmlab.gui.app.messagebox.showerror") as showerror:
                comparison_error(RuntimeError("对比任务出错"))
                showerror.assert_called_once()
            self.assertTrue(buttons["keys"].instate(["disabled"]))
            self.assertTrue(buttons["compare"].instate(["disabled"]))

            keys_ready(KEYRING)
            self.assertTrue(buttons["run"].instate(["!disabled"]))
            self.assertTrue(buttons["compare"].instate(["!disabled"]))
            self.assertEqual(self.app.world.steps, 0)

    def test_compare_all_in_background(self):
        self.app.compare_all()
        end = time.time() + 60
        windows = []
        while not windows and time.time() < end:
            self.root.update()
            windows = [w for w in self.root.winfo_children() if isinstance(w, tk.Toplevel)]
            time.sleep(0.01)
        self.assertTrue(windows, "对比窗口未出现")
        tree = [c for c in windows[0].winfo_children()][0]
        self.assertEqual(len(tree.get_children()), len(SCENARIO_BY_ID))


class GuiKeyGenerationTests(unittest.TestCase):
    def test_keys_generated_in_background_then_ui_enabled(self):
        from mitmlab.gui.app import App
        root = _shared_root()
        main_thread = threading.get_ident()
        calls = []
        original = App._on_keys_ready

        def spy(self, keyring):
            calls.append(threading.get_ident())
            original(self, keyring)

        App._on_keys_ready = spy
        self.addCleanup(setattr, App, "_on_keys_ready", original)
        app = _make_app(self, rsa_bits=1024)
        self.assertIsNone(app.keyring)
        self.assertTrue(app.buttons["run"].instate(["disabled"]))
        app.auth_var.set(True)
        app._on_config_changed()
        end = time.time() + 60
        while app.keyring is None and time.time() < end:
            root.update()
            time.sleep(0.01)
        self.assertIsNotNone(app.keyring)
        self.assertEqual(calls, [main_thread])  # 回调始终在主线程执行
        self.assertTrue(app.buttons["run"].instate(["!disabled"]))
        self.assertIsNotNone(app.world)
        self.assertTrue(app.world.profile.auth_kex)


if __name__ == "__main__":
    unittest.main()
