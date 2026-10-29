"""命令行入口测试：保证 README 里的演示命令可用，且场景对照表与预期一致。"""

import contextlib
import io
import unittest
from unittest import mock

from mitmlab import cli


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_list_shows_all_scenarios(self):
        code, out, _ = run_cli("list")
        self.assertEqual(code, 0)
        for sid in ("normal", "mitm", "defended-mitm", "replay"):
            self.assertIn(sid, out)

    def test_run_attack_scenario_prints_process_and_verdict(self):
        code, out, _ = run_cli("run", "mitm", "--rsa-bits", "1024")
        self.assertEqual(code, 0)
        self.assertIn("窃听", out)
        self.assertIn("攻击成功", out)
        self.assertNotIn("网络  ", out)  # 默认不显示网络层投递

    def test_run_defense_scenario(self):
        _, out, _ = run_cli("run", "defended-mitm", "--rsa-bits", "1024")
        self.assertIn("签名验证失败", out)
        self.assertIn("攻击未得逞", out)

    def test_verbose_shows_network_events(self):
        _, out, _ = run_cli("run", "normal", "--verbose", "--rsa-bits", "1024")
        self.assertIn("网络", out)

    def test_step_mode_non_interactive(self):
        with mock.patch("builtins.input", side_effect=EOFError):
            code, out, _ = run_cli("run", "normal", "--step", "--rsa-bits", "1024")
        self.assertEqual(code, 0)
        self.assertIn("攻击未得逞", out)

    def test_step_mode_waits_each_step(self):
        with mock.patch("builtins.input", return_value="") as fake_input:
            run_cli("run", "normal", "--step", "--rsa-bits", "1024")
        self.assertGreater(fake_input.call_count, 5)

    def test_unknown_scenario(self):
        code, _, err = run_cli("run", "nope")
        self.assertEqual(code, 2)
        self.assertIn("未知场景", err)

    def test_all_matches_expectations(self):
        code, out, _ = run_cli("all", "--rsa-bits", "1024")
        self.assertEqual(code, 0)
        self.assertNotIn("不一致", out)


if __name__ == "__main__":
    unittest.main()
