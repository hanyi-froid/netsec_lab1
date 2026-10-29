"""协议层单元测试：线路格式、网络信道（bytes 约束、网关路由、故障注入）、会话封装、握手校验。"""

import hmac as std_hmac
import hashlib
import unittest

from mitmlab.crypto import aes, dh
from mitmlab.crypto.hmac_hkdf import hkdf
from mitmlab.crypto.numtheory import bytes_to_int
from mitmlab.proto import events as ev
from mitmlab.proto import handshake as hs
from mitmlab.proto import messages as m
from mitmlab.proto.channel import FaultConfig, Network
from mitmlab.proto.identities import generate_keyring
from mitmlab.proto.profiles import HARDENED, MAC_ONLY, PLAIN, SecurityProfile
from mitmlab.proto.session import (DecryptError, IntegrityError, MalformedError, ReplayError,
                                   Session, derive_session_keys)

try:
    from Crypto.Cipher import AES as PyAES
    HAVE_PYCRYPTODOME = True
except ImportError:
    HAVE_PYCRYPTODOME = False

KEYRING = generate_keyring(1024)


class WireFormatTests(unittest.TestCase):
    def test_roundtrip_preserves_types(self):
        msg = m.Message(m.DATA, "Alice", "Bob", {"seq": 7, "iv": b"\x00\xff", "note": "中文", "ct": b""})
        wire = m.encode(msg)
        self.assertIsInstance(wire, bytes)
        self.assertEqual(m.decode(wire), msg)

    def test_encode_rejects_bad_input(self):
        with self.assertRaises(m.WireError):
            m.encode(m.Message("NOPE", "a", "b"))
        with self.assertRaises(m.WireError):
            m.encode(m.Message(m.DATA, "a", "b", {"x": 1.5}))
        with self.assertRaises(m.WireError):
            m.encode(m.Message(m.DATA, "a", "b", {"x": True}))

    def test_decode_rejects_malformed_wire_data(self):
        good = m.encode(m.Message(m.ALERT, "a", "b", {"reason": "x"}))
        bad_inputs = [
            b"", b"not json", b"\xff\xfe", b"[]", b"{}",
            good.replace(b'"ALERT"', b'"EVIL"'),
            good.replace(b'"reason":"x"', b'"reason":{"hex":"zz"}'),
            good.replace(b'"reason":"x"', b'"reason":{"hex":"00","x":1}'),
            good.replace(b'"reason":"x"', b'"reason":true'),
            good.replace(b'"reason":"x"', b'"reason":[1]'),
            good.replace(b'"from":"a"', b'"from":1'),
            b"x" * (m.MAX_WIRE_SIZE + 1),
        ]
        for data in bad_inputs:
            with self.subTest(data=data[:30]), self.assertRaises(m.WireError):
                m.decode(data)

    def test_decode_rejects_non_bytes(self):
        with self.assertRaises(m.WireError):
            m.decode("string")  # type: ignore[arg-type]

    def test_describe_handles_garbage(self):
        self.assertIn("无法解析", m.describe(b"garbage"))
        self.assertIn("DATA", m.describe(m.encode(m.Message(m.DATA, "A", "B", {"ct": b"\x01" * 40}))))


class _Sink:
    def __init__(self, name):
        self.name, self.got = name, []

    def on_wire(self, delivery):
        self.got.append(delivery)


def _net(**kw):
    log = ev.EventLog()
    net = Network(log, **kw)
    nodes = {n: _Sink(n) for n in ("Alice", "Bob", "Evil")}
    for n in nodes.values():
        net.register(n)
    return net, nodes, log


class NetworkTests(unittest.TestCase):
    def test_only_bytes_allowed(self):
        net, _, _ = _net()
        for bad in ("text", m.Message(m.DATA, "a", "b"), {"a": 1}, 123, None):
            with self.subTest(bad=type(bad).__name__), self.assertRaises(TypeError):
                net.send("Alice", "Bob", bad)

    def test_unknown_destination(self):
        net, _, _ = _net()
        with self.assertRaises(KeyError):
            net.send("Alice", "Mallory", b"x")

    def test_sender_buffer_mutation_does_not_affect_wire(self):
        net, nodes, _ = _net()
        buf = bytearray(b"hello")
        net.send("Alice", "Bob", buf)
        buf[0] = 0
        net.run_until_idle()
        self.assertEqual(nodes["Evil"].got[0].data, b"hello")
        self.assertIs(type(nodes["Evil"].got[0].data), bytes)

    def test_gateway_routes_through_evil(self):
        net, nodes, _ = _net()
        net.send("Alice", "Bob", b"1")
        net.send("Bob", "Alice", b"2")
        net.send("Evil", "Bob", b"3")  # 网关自己发出的直达目的地
        net.run_until_idle()
        self.assertEqual([(d.src, d.dst) for d in nodes["Evil"].got], [("Alice", "Bob"), ("Bob", "Alice")])
        self.assertEqual([d.data for d in nodes["Bob"].got], [b"3"])

    def test_step_by_step_and_idle_guard(self):
        net, nodes, _ = _net()
        net.send("Evil", "Bob", b"a")
        net.send("Evil", "Bob", b"b")
        self.assertEqual(net.pending(), 2)
        self.assertEqual(net.step().data, b"a")
        self.assertEqual(net.pending(), 1)
        net.run_until_idle()
        self.assertIsNone(net.step())

        class Loop:
            name = "Loop"

            def on_wire(self, d):
                net2.send("Evil", "Loop", d.data)

        log = ev.EventLog()
        net2 = Network(log)
        net2.register(Loop())
        net2.register(_Sink("Evil"))
        net2.send("Evil", "Loop", b"x")
        with self.assertRaises(RuntimeError):
            net2.run_until_idle(max_steps=50)

    def test_fault_injection_is_deterministic(self):
        def run(seed):
            net, nodes, _ = _net(faults=FaultConfig(drop_rate=0.5, duplicate_rate=0.3, reorder_rate=0.3, seed=seed))
            for i in range(30):
                net.send("Evil", "Bob", bytes([i]))
            net.run_until_idle()
            return [d.data for d in nodes["Bob"].got]

        self.assertEqual(run(1), run(1))
        self.assertNotEqual(run(1), run(2))

    def test_extreme_fault_rates(self):
        net, nodes, log = _net(faults=FaultConfig(drop_rate=1.0))
        net.send("Evil", "Bob", b"x")
        net.run_until_idle()
        self.assertEqual(nodes["Bob"].got, [])
        self.assertTrue(log.of_kind(ev.FAULT))
        net, nodes, _ = _net(faults=FaultConfig(duplicate_rate=1.0))
        net.send("Evil", "Bob", b"x")
        net.run_until_idle()
        self.assertEqual(len(nodes["Bob"].got), 2)


def _sessions(profile):
    keys = derive_session_keys(b"\x01" * 192, b"n" * 16, b"m" * 16)
    return Session(keys, "A", profile), Session(keys, "B", profile)


class SessionTests(unittest.TestCase):
    def test_key_derivation_matches_hkdf_split(self):
        k = derive_session_keys(b"secret", b"A" * 16, b"B" * 16)
        okm = hkdf(b"secret", 96, salt=b"A" * 16 + b"B" * 16, info=b"mitmlab-v1 session keys")
        self.assertEqual(k.a2b_enc + k.a2b_mac + k.b2a_enc + k.b2a_mac, okm)
        self.assertEqual(len({k.a2b_enc, k.b2a_enc, k.a2b_mac, k.b2a_mac}), 4)
        self.assertNotEqual(derive_session_keys(b"secret", b"A" * 16, b"C" * 16), k)

    def test_roundtrip_both_directions(self):
        a, b = _sessions(HARDENED)
        self.assertEqual(b.open(a.seal("你好".encode())), "你好".encode())
        self.assertEqual(a.open(b.seal(b"reply")), b"reply")

    def test_wire_format_against_independent_implementations(self):
        # 用标准库 hmac 与 pycryptodome 独立核对封装格式：密文可被库解密，MAC 等于库计算值
        keys = derive_session_keys(b"\x02" * 192, b"n" * 16, b"m" * 16)
        a = Session(keys, "A", HARDENED)
        pkt = a.seal(b"independent check")
        expect_mac = std_hmac.new(keys.a2b_mac, b"A2B" + pkt["seq"].to_bytes(8, "big") + pkt["iv"] + pkt["ct"],
                                  hashlib.sha256).digest()
        self.assertEqual(pkt["mac"], expect_mac)
        if HAVE_PYCRYPTODOME:
            raw = PyAES.new(keys.a2b_enc, PyAES.MODE_CBC, pkt["iv"]).decrypt(pkt["ct"])
            self.assertEqual(raw[:-raw[-1]], b"independent check")

    def test_sequence_numbers_increase_and_ivs_differ(self):
        a, _ = _sessions(HARDENED)
        p1, p2 = a.seal(b"x"), a.seal(b"x")
        self.assertEqual((p1["seq"], p2["seq"]), (1, 2))
        self.assertNotEqual(p1["iv"], p2["iv"])
        self.assertNotEqual(p1["ct"], p2["ct"])

    def test_any_tampered_field_fails_mac(self):
        a, b = _sessions(HARDENED)
        pkt = a.seal(b"pay 100")
        for field in ("iv", "ct", "mac"):
            bad = dict(pkt)
            raw = bytearray(bad[field])
            raw[0] ^= 1
            bad[field] = bytes(raw)
            with self.subTest(field=field), self.assertRaises(IntegrityError):
                b.open(bad)
        bad = dict(pkt, seq=pkt["seq"] + 1)  # 修改 seq 同样会使 MAC 失效
        with self.assertRaises(IntegrityError):
            b.open(bad)

    def test_replay_rejected_when_enabled(self):
        a, b = _sessions(HARDENED)
        p1, p2 = a.seal(b"one"), a.seal(b"two")
        self.assertEqual(b.open(p1), b"one")
        with self.assertRaises(ReplayError):
            b.open(p1)
        self.assertEqual(b.open(p2), b"two")
        with self.assertRaises(ReplayError):
            b.open(p1)

    def test_gap_in_sequence_is_allowed(self):
        a, b = _sessions(HARDENED)
        a.seal(b"lost")
        self.assertEqual(b.open(a.seal(b"after loss")), b"after loss")

    def test_replay_accepted_when_disabled(self):
        a, b = _sessions(MAC_ONLY)
        pkt = a.seal(b"one")
        self.assertEqual(b.open(pkt), b"one")
        self.assertEqual(b.open(pkt), b"one")

    def test_reflection_blocked_by_directional_keys(self):
        a, _ = _sessions(HARDENED)
        with self.assertRaises(IntegrityError):
            a.open(a.seal(b"echo"))  # 把 A 发出的包原样喂回 A

    def test_without_mac_tampering_goes_undetected(self):
        a, b = _sessions(PLAIN)
        pkt = a.seal(b"A" * 20 + b"transfer 100")
        ct = bytearray(pkt["ct"])
        ct[0] ^= 1
        pkt["ct"] = bytes(ct)
        self.assertNotEqual(b.open(pkt), b"A" * 20 + b"transfer 100")  # 解出被改动的明文而无任何报错

    def test_malformed_packets(self):
        _, b = _sessions(HARDENED)
        good = {"seq": 1, "iv": b"\x00" * 16, "ct": b"\x00" * 16, "mac": b"\x00" * 32}
        for key, value in (("seq", 0), ("seq", "1"), ("seq", True), ("seq", 1 << 63), ("iv", b"short"),
                           ("ct", b""), ("ct", b"x" * 15), ("mac", "str"), ("iv", None)):
            with self.subTest(key=key, value=value), self.assertRaises(MalformedError):
                b.open(dict(good, **{key: value}))
        with self.assertRaises(MalformedError):
            b.open({})

    def test_bad_padding_without_mac_raises_decrypt_error(self):
        a, b = _sessions(PLAIN)
        pkt = a.seal(b"hello")
        pkt["ct"] = bytes(16)  # 垃圾密文，去填充必然失败
        with self.assertRaises(DecryptError):
            b.open(pkt)

    def test_invalid_role(self):
        with self.assertRaises(ValueError):
            Session(derive_session_keys(b"s", b"a", b"b"), "C", PLAIN)

    def test_fingerprint_is_stable(self):
        k = derive_session_keys(b"s", b"a" * 16, b"b" * 16)
        self.assertEqual(k.fingerprint(), k.fingerprint())
        self.assertEqual(len(k.fingerprint()), 12)


class HandshakeTests(unittest.TestCase):
    def _auth_pair(self):
        init, st_a = hs.build_init("Alice", "Bob", KEYRING.alice)
        y_a, n_a = hs.process_init(init, "Bob", "Alice", KEYRING.alice.public)
        reply, st_b = hs.build_reply("Bob", "Alice", y_a, n_a, KEYRING.bob)
        return init, st_a, reply, st_b

    def test_authenticated_handshake_agrees_on_keys(self):
        init, st_a, reply, st_b = self._auth_pair()
        y_b, n_b = hs.process_reply(reply, "Alice", "Bob", st_a, KEYRING.bob.public)
        k_a = hs.derive_keys(st_a, y_b, st_a.nonce, n_b)
        k_b = hs.derive_keys(st_b, st_a.y, st_a.nonce, st_b.nonce)
        self.assertEqual(k_a, k_b)

    def test_replaced_dh_key_breaks_signature(self):
        init, _, _, _ = self._auth_pair()
        evil_init, _ = hs.build_init("Alice", "Bob", None)
        forged = init.copy()
        forged.fields["dh_pub"] = evil_init.fields["dh_pub"]
        with self.assertRaisesRegex(hs.HandshakeError, "签名"):
            hs.process_init(forged, "Bob", "Alice", KEYRING.alice.public)

    def test_signature_by_wrong_key_rejected(self):
        forged, _ = hs.build_init("Alice", "Bob", KEYRING.evil)
        with self.assertRaisesRegex(hs.HandshakeError, "签名"):
            hs.process_init(forged, "Bob", "Alice", KEYRING.alice.public)

    def test_missing_signature_rejected_when_required(self):
        unsigned, _ = hs.build_init("Alice", "Bob", None)
        with self.assertRaises(hs.HandshakeError):
            hs.process_init(unsigned, "Bob", "Alice", KEYRING.alice.public)
        hs.process_init(unsigned, "Bob", "Alice", None)  # 未启用认证时可接受

    def test_reply_is_bound_to_this_session(self):
        # 旧会话中 Bob 的合法应答，不能用于新会话（签名覆盖了 Alice 的 DH 公钥与 nonce）
        _, _, old_reply, _ = self._auth_pair()
        _, new_state = hs.build_init("Alice", "Bob", KEYRING.alice)
        with self.assertRaisesRegex(hs.HandshakeError, "签名"):
            hs.process_reply(old_reply, "Alice", "Bob", new_state, KEYRING.bob.public)

    def test_identity_binding(self):
        init, _, _, _ = self._auth_pair()
        with self.assertRaises(hs.HandshakeError):
            hs.process_init(init, "Carol", "Alice", KEYRING.alice.public)  # 收件人不对
        with self.assertRaises(hs.HandshakeError):
            hs.process_init(init, "Bob", "Mallory", KEYRING.alice.public)  # 发件人不对

    def test_invalid_dh_public_values_rejected(self):
        p = dh.RFC3526_1536_P
        for bad in (0, 1, p - 1, p):
            init, _ = hs.build_init("Alice", "Bob", None)
            init.fields["dh_pub"] = bad.to_bytes(192, "big")
            with self.subTest(y=bad), self.assertRaisesRegex(hs.HandshakeError, "DH 公钥"):
                hs.process_init(init, "Bob", "Alice", None)

    def test_malformed_fields_rejected(self):
        init, _ = hs.build_init("Alice", "Bob", None)
        for field, value in (("dh_pub", b"short"), ("nonce", b"x"), ("dh_pub", "text"), ("nonce", 5)):
            bad = init.copy()
            bad.fields[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(hs.HandshakeError):
                hs.process_init(bad, "Bob", "Alice", None)
        wrong_type, _ = hs.build_reply("Bob", "Alice", init.fields["dh_pub"], init.fields["nonce"])
        with self.assertRaises(hs.HandshakeError):
            hs.process_init(wrong_type, "Bob", "Alice", None)

    def test_transcripts_are_unambiguous(self):
        # 长度前缀保证 ("ab","c") 与 ("a","bc") 得到不同的签名原文
        self.assertNotEqual(hs.init_transcript("ab", "c", b"y", b"n"), hs.init_transcript("a", "bc", b"y", b"n"))


if __name__ == "__main__":
    unittest.main()
