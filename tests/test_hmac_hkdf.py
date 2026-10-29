"""HMAC-SHA256 与 HKDF-SHA256 单元测试。

依据：
  1. RFC 4231 给出的 HMAC-SHA256 官方测试向量（含密钥长于分组的用例 6、7）；
  2. RFC 5869 附录 A 的 HKDF-SHA256 官方测试向量（含空 salt/info 的用例 3）；
  3. 与标准库 hmac、pycryptodome（若已安装）对照。
"""

import hmac as std_hmac
import hashlib
import random
import unittest

from mitmlab.crypto.hmac_hkdf import (
    constant_time_equal, hkdf, hkdf_expand, hkdf_extract, hmac_sha256,
)

try:
    from Crypto.Protocol.KDF import HKDF as PyCryptoHKDF
    from Crypto.Hash import SHA256 as PyCryptoSHA256
    HAVE_PYCRYPTODOME = True
except ImportError:  # 未安装测试依赖时跳过库对照，静态向量仍会执行
    HAVE_PYCRYPTODOME = False

# (key, data, 期望 HMAC-SHA256)，RFC 4231 第 4.2~4.8 节
RFC4231 = [
    (b"\x0b" * 20, b"Hi There",
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    (b"Jefe", b"what do ya want for nothing?",
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    (b"\xaa" * 20, b"\xdd" * 50,
     "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
    (bytes(range(1, 26)), b"\xcd" * 50,
     "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
    (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First",
     "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
    (b"\xaa" * 131,
     b"This is a test using a larger than block-size key and a larger than "
     b"block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
     "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
]


class HmacTests(unittest.TestCase):
    def test_rfc4231_vectors(self):
        for i, (key, data, expected) in enumerate(RFC4231):
            with self.subTest(case=i):
                self.assertEqual(hmac_sha256(key, data).hex(), expected)

    def test_random_inputs_match_stdlib(self):
        rng = random.Random(4231)
        for _ in range(200):
            key = rng.randbytes(rng.randint(0, 200))  # 覆盖空密钥、分组边界与超长密钥
            msg = rng.randbytes(rng.randint(0, 300))
            self.assertEqual(hmac_sha256(key, msg),
                             std_hmac.new(key, msg, hashlib.sha256).digest())

    def test_block_size_key_boundaries(self):
        for klen in (63, 64, 65):
            key = bytes(range(klen))
            self.assertEqual(hmac_sha256(key, b"m"),
                             std_hmac.new(key, b"m", hashlib.sha256).digest())

    def test_constant_time_equal(self):
        self.assertTrue(constant_time_equal(b"abc", b"abc"))
        self.assertFalse(constant_time_equal(b"abc", b"abd"))
        self.assertFalse(constant_time_equal(b"abc", b"ab"))
        self.assertTrue(constant_time_equal(b"", b""))


class HkdfTests(unittest.TestCase):
    def test_rfc5869_case1(self):
        ikm = b"\x0b" * 22
        salt = bytes(range(0x00, 0x0D))
        info = bytes(range(0xF0, 0xFA))
        prk = hkdf_extract(salt, ikm)
        self.assertEqual(prk.hex(),
                         "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        self.assertEqual(
            hkdf_expand(prk, info, 42).hex(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

    def test_rfc5869_case2_long_inputs(self):
        ikm = bytes(range(0x00, 0x50))
        salt = bytes(range(0x60, 0xB0))
        info = bytes(range(0xB0, 0x100))
        self.assertEqual(
            hkdf(ikm, 82, salt, info).hex(),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f1d87")

    def test_rfc5869_case3_empty_salt_and_info(self):
        ikm = b"\x0b" * 22
        self.assertEqual(
            hkdf_extract(b"", ikm).hex(),
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
        self.assertEqual(
            hkdf(ikm, 42).hex(),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")

    @unittest.skipUnless(HAVE_PYCRYPTODOME, "需要 pycryptodome 做库对照")
    def test_random_inputs_match_pycryptodome(self):
        rng = random.Random(5869)
        for _ in range(50):
            ikm = rng.randbytes(rng.randint(1, 64))
            salt = rng.randbytes(rng.randint(1, 40))
            info = rng.randbytes(rng.randint(0, 40))
            length = rng.randint(1, 200)
            expected = PyCryptoHKDF(ikm, length, salt, PyCryptoSHA256, context=info)
            self.assertEqual(hkdf(ikm, length, salt, info), expected)

    def test_output_too_long_rejected(self):
        with self.assertRaises(ValueError):
            hkdf(b"k", 255 * 32 + 1)


if __name__ == "__main__":
    unittest.main()
