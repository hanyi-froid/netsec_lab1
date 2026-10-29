"""Diffie-Hellman 单元测试。

依据：
  1. RFC 3526 1536 位 MODP 群：素数结构（首尾 64 位全 1）、p 与 (p-1)/2 均为素数，
     并用独立计算的 π 校验 p = 2^1536 - 2^1472 - 1 + 2^64 * (⌊2^1406 π⌋ + 741804)，
     即不依赖手工抄录的十六进制文本；
  2. 公钥、共享秘密与 Python 内置 pow 对照（固定私钥）；
  3. 非法公钥（0、1、p-1、p、非子群元素等）必须被拒绝。
"""

import unittest

from mitmlab.crypto import dh
from mitmlab.crypto.numtheory import is_probable_prime


def _arctan_inv(x: int, scale: int) -> int:
    """定点数计算 arctan(1/x)*scale（泰勒级数），仅用于测试中独立求 π。"""
    total = term = scale // x
    x2, n, sign = x * x, 1, -1
    while term:
        term //= x2
        n += 2
        total += sign * (term // n)
        sign = -sign
    return total


def floor_pi_times_2_pow(k: int) -> int:
    """返回 ⌊2^k · π⌋，用 Machin 公式 π = 16·arctan(1/5) - 4·arctan(1/239)。"""
    guard = 64
    scale = 1 << (k + guard)
    pi_scaled = 16 * _arctan_inv(5, scale) - 4 * _arctan_inv(239, scale)
    return pi_scaled >> guard


class Rfc3526GroupTests(unittest.TestCase):
    def test_bit_length_and_generator(self):
        self.assertEqual(dh.RFC3526_1536_P.bit_length(), 1536)
        self.assertEqual(dh.RFC3526_1536_G, 2)

    def test_prime_matches_pi_formula(self):
        p = dh.RFC3526_1536_P
        expected = (1 << 1536) - (1 << 1472) - 1 + (1 << 64) * (floor_pi_times_2_pow(1406) + 741804)
        self.assertEqual(p, expected)

    def test_is_safe_prime(self):
        p = dh.RFC3526_1536_P
        self.assertTrue(is_probable_prime(p, rounds=10))
        self.assertTrue(is_probable_prime((p - 1) // 2, rounds=10))

    def test_generator_has_prime_order_q(self):
        g = dh.GROUP_1536
        self.assertEqual(pow(g.g, g.q, g.p), 1)  # 2 是二次剩余，属于阶 q 子群


class KeyExchangeTests(unittest.TestCase):
    def test_public_and_shared_match_builtin_pow(self):
        grp = dh.GROUP_1536
        xa, xb = 0x1234567890ABCDEF1234567890ABCDEF, 0xFEDCBA0987654321FEDCBA0987654321
        ya, yb = dh.public_from_private(xa, grp), dh.public_from_private(xb, grp)
        self.assertEqual(ya, pow(grp.g, xa, grp.p))
        self.assertEqual(yb, pow(grp.g, xb, grp.p))
        expected = pow(grp.g, xa * xb, grp.p).to_bytes(grp.byte_len, "big")
        self.assertEqual(dh.shared_secret(xa, yb, grp), expected)
        self.assertEqual(dh.shared_secret(xb, ya, grp), expected)

    def test_random_keypairs_agree(self):
        xa, ya = dh.generate_keypair()
        xb, yb = dh.generate_keypair()
        self.assertEqual(dh.shared_secret(xa, yb), dh.shared_secret(xb, ya))
        self.assertEqual(len(dh.shared_secret(xa, yb)), 192)

    def test_private_key_range(self):
        for _ in range(20):
            x = dh.generate_private()
            self.assertTrue(2 <= x < dh.GROUP_1536.q)

    def test_public_serialization(self):
        _, y = dh.generate_keypair()
        raw = dh.public_to_bytes(y)
        self.assertEqual(len(raw), 192)
        self.assertEqual(dh.public_from_bytes(raw), y)


class PublicKeyValidationTests(unittest.TestCase):
    def test_degenerate_values_rejected(self):
        p = dh.RFC3526_1536_P
        for bad in (-1, 0, 1, p - 1, p, p + 1, 2 * p):
            with self.subTest(y=bad), self.assertRaises(dh.InvalidPublicKey):
                dh.validate_public(bad)

    def test_non_subgroup_element_rejected(self):
        # p-2 = -2 是二次非剩余（-1 为非剩余、2 为剩余），不在阶 q 子群内
        with self.assertRaises(dh.InvalidPublicKey):
            dh.validate_public(dh.RFC3526_1536_P - 2)

    def test_valid_values_accepted(self):
        dh.validate_public(2)
        _, y = dh.generate_keypair()
        dh.validate_public(y)

    def test_shared_secret_refuses_bad_peer_key(self):
        x, _ = dh.generate_keypair()
        for bad in (0, 1, dh.RFC3526_1536_P - 1):
            with self.subTest(y=bad), self.assertRaises(dh.InvalidPublicKey):
                dh.shared_secret(x, bad)


if __name__ == "__main__":
    unittest.main()
