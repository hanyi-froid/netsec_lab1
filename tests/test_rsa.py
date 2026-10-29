"""RSA 与 PKCS#1 v1.5 签名单元测试。

依据：
  1. 教科书小素数示例（p=61, q=53, e=17 → d=413 / φ 版 2753）校验密钥推导；
  2. SHA-256 DigestInfo 前缀的 DER 字节、EMSA-PKCS1-v1_5 编码结构；
  3. 与 pycryptodome pkcs1_15 交叉验证：同一密钥下签名字节完全一致（PKCS#1 v1.5 签名是确定性的），
     自实现验签能通过库产生的签名，库验签能通过自实现产生的签名；
  4. 各类伪造/篡改输入必须验签失败。
"""

import unittest

from mitmlab.crypto import rsa
from mitmlab.crypto.numtheory import bytes_to_int, int_to_bytes
from mitmlab.crypto.sha256 import sha256

try:
    from Crypto.PublicKey import RSA as PyRSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256 as PySHA256
    HAVE_PYCRYPTODOME = True
except ImportError:
    HAVE_PYCRYPTODOME = False


class KeyDerivationTests(unittest.TestCase):
    def test_textbook_example(self):
        key = rsa.key_from_primes(61, 53, 17)
        self.assertEqual(key.n, 3233)
        # 使用 λ(n)=lcm(60,52)=780 时 d=413；教科书 φ=3120 给出 2753，二者对 e 等价
        self.assertEqual(key.d, 413)
        self.assertEqual(key.d * key.e % 780, 1)
        for m in (0, 1, 65, 3232):
            self.assertEqual(pow(pow(m, key.e, key.n), key.d, key.n), m)

    def test_invalid_primes(self):
        with self.assertRaises(ValueError):
            rsa.key_from_primes(61, 61, 17)
        with self.assertRaises(ValueError):
            rsa.key_from_primes(61, 53, 13)  # gcd(13, 780) = 13

    def test_generated_key_properties(self):
        key = rsa.generate_keypair(512)
        self.assertEqual(key.n.bit_length(), 512)
        self.assertEqual(key.p * key.q, key.n)
        self.assertNotEqual(key.p, key.q)
        lam = (key.p - 1) * (key.q - 1) // _gcd(key.p - 1, key.q - 1)
        self.assertEqual(key.e * key.d % lam, 1)

    def test_invalid_key_sizes(self):
        for bits in (256, 513):
            with self.assertRaises(ValueError):
                rsa.generate_keypair(bits)

    def test_key_serialization_roundtrip(self):
        key = rsa.generate_keypair(512)
        self.assertEqual(rsa.RSAPrivateKey.from_dict(key.to_dict()), key)
        self.assertEqual(rsa.RSAPublicKey.from_dict(key.public.to_dict()), key.public)
        self.assertEqual(len(key.public.fingerprint()), 16)


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


class EncodingTests(unittest.TestCase):
    def test_digestinfo_prefix_bytes(self):
        # RFC 8017 第 9.2 节注 1：SHA-256 的 DigestInfo DER 前缀
        self.assertEqual(rsa.SHA256_DIGESTINFO_PREFIX.hex(), "3031300d060960864801650304020105000420")
        self.assertEqual(len(rsa.SHA256_DIGESTINFO_PREFIX), 19)

    def test_emsa_structure(self):
        em = rsa.emsa_pkcs1_v15_encode(b"hello", 128)
        self.assertEqual(len(em), 128)
        self.assertEqual(em[:2], b"\x00\x01")
        t = rsa.SHA256_DIGESTINFO_PREFIX + sha256(b"hello")
        self.assertEqual(em[-len(t):], t)
        self.assertEqual(em[-len(t) - 1], 0x00)
        self.assertEqual(set(em[2:-len(t) - 1]), {0xFF})
        self.assertGreaterEqual(len(em) - len(t) - 3, 8)  # 填充至少 8 字节

    def test_too_short_modulus_rejected(self):
        with self.assertRaises(ValueError):
            rsa.emsa_pkcs1_v15_encode(b"x", 60)


class SignVerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_keypair(1024)
        cls.pub = cls.key.public

    def test_sign_verify(self):
        sig = rsa.sign(self.key, b"transfer 100 yuan to Bob")
        self.assertEqual(len(sig), 128)
        self.assertTrue(rsa.verify(self.pub, b"transfer 100 yuan to Bob", sig))

    def test_signature_is_deterministic(self):
        self.assertEqual(rsa.sign(self.key, b"m"), rsa.sign(self.key, b"m"))

    def test_tampered_message_rejected(self):
        sig = rsa.sign(self.key, b"transfer 100")
        self.assertFalse(rsa.verify(self.pub, b"transfer 10000", sig))

    def test_tampered_signature_rejected(self):
        sig = bytearray(rsa.sign(self.key, b"msg"))
        for pos in (0, 64, 127):
            bad = bytearray(sig)
            bad[pos] ^= 0x01
            self.assertFalse(rsa.verify(self.pub, b"msg", bytes(bad)))

    def test_wrong_key_rejected(self):
        other = rsa.generate_keypair(1024)
        sig = rsa.sign(other, b"msg")
        self.assertFalse(rsa.verify(self.pub, b"msg", sig))

    def test_malformed_signatures_rejected(self):
        sig = rsa.sign(self.key, b"msg")
        self.assertFalse(rsa.verify(self.pub, b"msg", sig[:-1]))
        self.assertFalse(rsa.verify(self.pub, b"msg", sig + b"\x00"))
        self.assertFalse(rsa.verify(self.pub, b"msg", b""))
        self.assertFalse(rsa.verify(self.pub, b"msg", int_to_bytes(self.pub.n, 128)))  # s == n

    def test_forged_padding_rejected(self):
        # 用私钥对"畸形编码"签名，验签必须拒绝：缺少 NULL 参数的 DigestInfo、错误的填充字节
        k = 128
        digest = sha256(b"msg")
        bad_info = bytes.fromhex("302f300b0609608648016503040201") + b"\x04\x20" + digest
        em1 = b"\x00\x01" + b"\xff" * (k - len(bad_info) - 3) + b"\x00" + bad_info
        t = rsa.SHA256_DIGESTINFO_PREFIX + digest
        em2 = b"\x00\x01" + b"\xfe" * (k - len(t) - 3) + b"\x00" + t
        for em in (em1, em2):
            sig = int_to_bytes(rsa._private_op(self.key, bytes_to_int(em)), k)
            self.assertFalse(rsa.verify(self.pub, b"msg", sig))


@unittest.skipUnless(HAVE_PYCRYPTODOME, "需要 pycryptodome 做库对照")
class CrossCheckWithPycryptodome(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_keypair(1024)
        cls.lib_priv = PyRSA.construct((cls.key.n, cls.key.e, cls.key.d, cls.key.p, cls.key.q))

    def test_library_accepts_our_key_as_valid(self):
        self.assertTrue(self.lib_priv.has_private())  # construct 会校验 n=p*q 与 e*d 关系

    def test_signature_bytes_identical_to_library(self):
        for msg in (b"", b"abc", b"transfer 100 yuan", bytes(range(256)) * 3):
            with self.subTest(len=len(msg)):
                expected = pkcs1_15.new(self.lib_priv).sign(PySHA256.new(msg))
                self.assertEqual(rsa.sign(self.key, msg), expected)

    def test_library_verifies_our_signature(self):
        msg = "中间人攻击".encode()
        sig = rsa.sign(self.key, msg)
        pkcs1_15.new(self.lib_priv.publickey()).verify(PySHA256.new(msg), sig)  # 失败会抛 ValueError

    def test_we_verify_library_signature(self):
        msg = b"signed by library"
        sig = pkcs1_15.new(self.lib_priv).sign(PySHA256.new(msg))
        self.assertTrue(rsa.verify(self.key.public, msg, sig))
        self.assertFalse(rsa.verify(self.key.public, msg + b"!", sig))

    def test_library_rejects_what_we_reject(self):
        sig = bytearray(rsa.sign(self.key, b"x"))
        sig[10] ^= 0xFF
        with self.assertRaises(ValueError):
            pkcs1_15.new(self.lib_priv.publickey()).verify(PySHA256.new(b"x"), bytes(sig))
        self.assertFalse(rsa.verify(self.key.public, b"x", bytes(sig)))

    def test_2048_bit_signature_matches_library(self):
        key = rsa.generate_keypair(2048)
        lib = PyRSA.construct((key.n, key.e, key.d, key.p, key.q))
        self.assertEqual(rsa.sign(key, b"2048"), pkcs1_15.new(lib).sign(PySHA256.new(b"2048")))


if __name__ == "__main__":
    unittest.main()
