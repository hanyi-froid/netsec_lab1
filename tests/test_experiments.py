"""自动化实验、性能分析与相关 CLI 命令的测试。"""

import contextlib
import csv
import io
import os
import tempfile
import unittest

from mitmlab import cli, experiments, perf
from mitmlab.proto.attacker import MODE_LABELS, EvilMode
from mitmlab.proto.identities import generate_keyring

KEYRING = generate_keyring(1024)


class DefenseMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = experiments.defense_matrix(KEYRING)
        cls.cell = {(r["attack"], r["profile"]): r["attack_succeeded"] for r in cls.rows}

    def test_matrix_is_complete(self):
        self.assertEqual(len(self.rows), 4 * 3)

    def test_expected_attack_defense_relationships(self):
        # (攻击, 无防御, 仅 HMAC, 完整防御) 的攻击是否得逞
        expected = {
            EvilMode.MITM: (True, True, False),
            EvilMode.IMPERSONATE: (True, True, False),
            EvilMode.BITFLIP: (True, False, False),
            EvilMode.REPLAY: (True, True, False),
        }
        for mode, outcomes in expected.items():
            for profile, want in zip(("无防御", "仅 HMAC", "完整防御"), outcomes):
                with self.subTest(attack=mode.value, profile=profile):
                    self.assertEqual(self.cell[(MODE_LABELS[mode], profile)], want)


class RepeatTests(unittest.TestCase):
    def test_results_are_stable_across_random_runs(self):
        for row in experiments.scenario_repeats(KEYRING, repeats=3):
            with self.subTest(row["scenario"]):
                self.assertIn(row["attack_rate"], (0.0, 1.0))  # 随机数不同也不改变结论
                self.assertEqual(row["attack_rate"] == 1.0, row["expected_attack"])


class FaultExperimentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = experiments.fault_experiment(KEYRING, trials=6)
        cls.by = {(r["profile"], r["fault"]): r for r in cls.rows}

    def test_no_fault_always_works(self):
        for profile in ("无防御", "完整防御"):
            self.assertEqual(self.by[(profile, "无故障")]["comm_ok_rate"], 1.0)

    def test_loss_hurts_both_profiles(self):
        for profile in ("无防御", "完整防御"):
            self.assertLess(self.by[(profile, "丢包 30%")]["comm_ok_rate"], 1.0)

    def test_duplicates_only_break_unprotected_communication(self):
        self.assertLess(self.by[("无防御", "重复 30%")]["comm_ok_rate"], 1.0)
        self.assertEqual(self.by[("完整防御", "重复 30%")]["comm_ok_rate"], 1.0)

    def test_deterministic(self):
        again = experiments.fault_experiment(KEYRING, trials=6)
        self.assertEqual(again, self.rows)


class CsvTests(unittest.TestCase):
    def test_write_and_read_back(self):
        rows = [{"a": 1, "b": "中文"}, {"a": 2, "b": "x"}]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sub", "out.csv")
            experiments.write_csv(path, rows)
            with open(path, encoding="utf-8-sig", newline="") as f:
                read = list(csv.DictReader(f))
        self.assertEqual(read, [{"a": "1", "b": "中文"}, {"a": "2", "b": "x"}])

    def test_empty_rows_rejected(self):
        with self.assertRaises(ValueError):
            experiments.write_csv("unused.csv", [])


class PerfTests(unittest.TestCase):
    def test_quick_benchmarks_produce_positive_numbers(self):
        rows = perf.run_benchmarks(quick=True, keyring=KEYRING)
        names = [r["item"] for r in rows]
        for keyword in ("RSA-1024 密钥生成", "签名", "验签", "DH-1536", "AES-128-CBC 加密", "SHA-256",
                        "HMAC", "无防御", "完整防御"):
            self.assertTrue(any(keyword in n for n in names), keyword)
        for r in rows:
            self.assertGreater(r["value"], 0, r["item"])


def run_cli(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(list(argv))
    return code, out.getvalue()


class CliBonusTests(unittest.TestCase):
    def test_matrix_command(self):
        code, out = run_cli("matrix", "--rsa-bits", "1024")
        self.assertEqual(code, 0)
        self.assertIn("被阻止", out)
        self.assertIn("攻击得逞", out)

    def test_experiments_command_writes_csv(self):
        with tempfile.TemporaryDirectory() as d:
            code, out = run_cli("experiments", "--trials", "2", "--rsa-bits", "1024", "--csv", d)
            self.assertEqual(code, 0)
            for name in ("matrix", "repeats", "faults"):
                self.assertTrue(os.path.exists(os.path.join(d, f"{name}.csv")))
        self.assertIn("异常情况模拟", out)

    def test_perf_command(self):
        code, out = run_cli("perf", "--quick")
        self.assertEqual(code, 0)
        self.assertIn("MB/s", out)

    def test_table_alignment_handles_wide_characters(self):
        text = cli.format_table([{"k": "中文", "v": True}, {"k": "ab", "v": False}], {"k": "键", "v": "值"})
        lines = text.splitlines()
        self.assertEqual(cli._display_width(lines[2].split("  ")[0]), cli._display_width("中文"))
        self.assertIn("是", text)
        self.assertIn("否", text)


if __name__ == "__main__":
    unittest.main()
