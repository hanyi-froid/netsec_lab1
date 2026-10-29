"""攻防场景集成测试：逐个场景断言"攻击是否得逞""防御后能否正常通信"，并检查关键细节。"""

import unittest

from mitmlab.proto import messages as m
from mitmlab.proto.attacker import EvilMode
from mitmlab.proto.channel import FaultConfig
from mitmlab.proto.identities import generate_keyring
from mitmlab.proto.roles import ABORTED, ESTABLISHED
from mitmlab.proto.scenarios import (ALICE_TEXT, BOB_TEXT, SCENARIO_BY_ID, SCENARIOS, World, run_scenario)

KEYRING = generate_keyring(1024)


def run(sid, **kw):
    return run_scenario(sid, keyring=KEYRING, **kw)


class ScenarioExpectationTests(unittest.TestCase):
    def test_every_scenario_matches_expected_outcome(self):
        for sc in SCENARIOS:
            with self.subTest(scenario=sc.id):
                r = run(sc.id)
                self.assertEqual(r.attack_succeeded, sc.attack_expected, r.summary)
                self.assertEqual(r.communication_ok, sc.comm_expected, r.summary)

    def test_scenario_ids_unique_and_cover_categories(self):
        self.assertEqual(len({s.id for s in SCENARIOS}), len(SCENARIOS))
        self.assertEqual({s.category for s in SCENARIOS}, {"normal", "attack", "defense"})


class NormalCommunicationTests(unittest.TestCase):
    def test_plain_normal(self):
        r = run("normal")
        self.assertEqual(r.bob_received, [ALICE_TEXT])
        self.assertEqual(r.alice_received, [BOB_TEXT])
        self.assertFalse(r.eavesdropped)  # Evil 只能看到密文
        self.assertEqual(r.fingerprints["Alice"], r.fingerprints["Bob"])
        self.assertEqual(r.alerts, [])

    def test_evil_sees_only_bytes_and_no_plaintext_on_wire(self):
        w = World(SCENARIO_BY_ID["normal"], keyring=KEYRING)
        w.run()
        for d in w.network.delivered:
            self.assertIs(type(d.data), bytes)
            m.decode(d.data)  # 线路上的每一条都是合法报文
            self.assertNotIn(ALICE_TEXT.encode(), d.data)
        for _, data in w.evil.captured:
            self.assertIs(type(data), bytes)

    def test_defended_normal(self):
        r = run("defended-normal")
        self.assertTrue(r.communication_ok)
        self.assertEqual((r.alice_state, r.bob_state), (ESTABLISHED, ESTABLISHED))
        self.assertEqual(r.alerts, [])
        self.assertEqual(r.fingerprints["Alice"], r.fingerprints["Bob"])


class AttackTests(unittest.TestCase):
    def test_mitm_key_substitution(self):
        r = run("mitm")
        f = r.fingerprints
        self.assertNotEqual(f["Alice"], f["Bob"])               # 双方以为在和对方通信，密钥却不同
        self.assertEqual(f["Evil↔Alice"], f["Alice"])           # Evil 持有与 Alice 相同的密钥
        self.assertEqual(f["Evil↔Bob"], f["Bob"])
        self.assertEqual(r.bob_received, [ALICE_TEXT.replace("100", "10000")])  # Bob 收到被篡改的金额
        self.assertEqual({t for _, t in r.evil_spied}, {ALICE_TEXT, BOB_TEXT})  # 双向明文都被窃听
        self.assertEqual(r.evil_tampered, [(ALICE_TEXT, ALICE_TEXT.replace("100", "10000"))])
        self.assertEqual(r.alerts, [])  # 双方毫无察觉

    def test_mitm_without_tamper_rule_only_eavesdrops(self):
        w = World(SCENARIO_BY_ID["mitm"], keyring=KEYRING)
        w.evil.tamper = None
        r = w.run()
        self.assertEqual(r.bob_received, [ALICE_TEXT])
        self.assertTrue(r.eavesdropped)
        self.assertEqual(r.evil_tampered, [])

    def test_mitm_custom_tamper(self):
        w = World(SCENARIO_BY_ID["mitm"], keyring=KEYRING)
        w.evil.tamper = lambda text: "Alice 说：全部转给 Evil"
        r = w.run()
        self.assertEqual(r.bob_received, ["Alice 说：全部转给 Evil"])

    def test_impersonation(self):
        r = run("impersonate")
        self.assertEqual(r.bob_state, "idle")  # 真正的 Bob 毫不知情
        self.assertEqual(r.alice_state, ESTABLISHED)
        self.assertEqual(r.bob_received, [])
        self.assertTrue(any("冒充" in t for t in r.alice_received))
        self.assertEqual([t for _, t in r.evil_spied], [ALICE_TEXT])

    def test_bitflip_without_mac_delivers_altered_text(self):
        r = run("bitflip")
        self.assertEqual(len(r.bob_received), 1)
        self.assertNotEqual(r.bob_received[0], ALICE_TEXT)
        self.assertEqual(r.alerts, [])

    def test_replay_without_protection_is_accepted_twice(self):
        r = run("replay")
        self.assertEqual(r.bob_received, [ALICE_TEXT, ALICE_TEXT])
        self.assertEqual(r.duplicates_accepted, 1)

    def test_manual_replay_api(self):
        w = World(SCENARIO_BY_ID["normal"], keyring=KEYRING)
        w.run()
        self.assertTrue(w.evil.replay(0))
        w.network.run_until_idle()
        self.assertEqual(w.bob.received.count(ALICE_TEXT), 2)
        self.assertFalse(w.evil.replay(5))


class LimitedDefenseTests(unittest.TestCase):
    def test_mac_alone_stops_bitflip(self):
        r = run("mac-vs-bitflip")
        self.assertEqual(r.bob_received, [])
        self.assertTrue(any("IntegrityError" in a for a in r.alerts))

    def test_mac_alone_does_not_stop_mitm(self):
        r = run("mac-vs-mitm")
        self.assertTrue(r.attack_succeeded)
        self.assertEqual(r.alerts, [])

    def test_mac_alone_does_not_stop_replay(self):
        self.assertEqual(run("mac-vs-replay").duplicates_accepted, 1)


class DefenseTests(unittest.TestCase):
    def test_signed_dh_stops_mitm(self):
        r = run("defended-mitm")
        self.assertEqual((r.alice_state, r.bob_state), (ABORTED, ABORTED))
        self.assertEqual(r.bob_received, [])
        self.assertEqual(r.alice_received, [])
        self.assertFalse(r.eavesdropped)
        self.assertTrue(any("签名验证失败" in a for a in r.alerts))
        self.assertEqual(r.evil_spied, [])

    def test_signed_dh_stops_impersonation(self):
        r = run("defended-impersonate")
        self.assertEqual(r.alice_state, ABORTED)
        self.assertTrue(any("签名验证失败" in a for a in r.alerts))
        self.assertFalse(r.attack_succeeded)

    def test_bitflip_blocked_with_full_defense(self):
        r = run("defended-bitflip")
        self.assertEqual(r.bob_received, [])
        self.assertTrue(r.defense_triggered)

    def test_replay_blocked_but_normal_flow_intact(self):
        r = run("defended-replay")
        self.assertEqual(r.bob_received, [ALICE_TEXT])
        self.assertTrue(any("ReplayError" in a for a in r.alerts))
        self.assertTrue(r.communication_ok)

    def test_pinned_key_absence_is_a_configuration_error(self):
        w = World(SCENARIO_BY_ID["defended-normal"], keyring=KEYRING)
        w.alice._trusted_peer_key = None
        with self.assertRaises(RuntimeError):
            w.run()

    def test_attacker_with_defended_profile_cannot_reuse_alice_signature(self):
        # Evil 即使在 MITM 时转发 Alice 的原始签名，也因 DH 公钥被替换而验签失败
        w = World(SCENARIO_BY_ID["defended-mitm"], keyring=KEYRING)
        w.run()
        self.assertEqual(w.evil.sessions, {})


class StepModeTests(unittest.TestCase):
    def test_stepping_equals_run(self):
        w = World(SCENARIO_BY_ID["mitm"], keyring=KEYRING)
        descriptions = []
        while True:
            d = w.step()
            if d is None:
                break
            descriptions.append(d)
        self.assertTrue(w.finished)
        self.assertGreater(len(descriptions), 8)
        self.assertEqual(w.analyze().bob_received, [ALICE_TEXT.replace("100", "10000")])

    def test_replay_scenario_needs_idle_step(self):
        w = World(SCENARIO_BY_ID["replay"], keyring=KEYRING)
        steps = []
        while (d := w.step()) is not None:
            steps.append(d)
        self.assertTrue(any("重放" in s for s in steps))
        self.assertTrue(w.finished)

    def test_event_log_records_actors(self):
        w = World(SCENARIO_BY_ID["mitm"], keyring=KEYRING)
        w.run()
        actors = {e.actor for e in w.log.events}
        self.assertTrue({"Alice", "Bob", "Evil", "网络"} <= actors)
        seen = []
        w2 = World(SCENARIO_BY_ID["normal"], keyring=KEYRING)
        w2.log.subscribe(seen.append)
        w2.run()
        self.assertEqual(len(seen), len(w2.log.events))


class FaultToleranceTests(unittest.TestCase):
    def test_total_packet_loss_does_not_crash(self):
        r = run("defended-normal", faults=FaultConfig(drop_rate=1.0))
        self.assertFalse(r.communication_ok)
        self.assertEqual(r.bob_received, [])

    def test_duplicated_packets_rejected_by_anti_replay(self):
        r = run("defended-normal", faults=FaultConfig(duplicate_rate=1.0))
        self.assertTrue(any("ReplayError" in a or "忽略意外" in a for a in r.alerts))
        self.assertEqual(r.bob_received, [ALICE_TEXT])


if __name__ == "__main__":
    unittest.main()
