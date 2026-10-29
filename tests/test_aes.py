"""AES 与 CBC/PKCS#7 单元测试。

依据：
  1. FIPS 197 附录 A（密钥扩展）、附录 B、附录 C（AES-128/192/256 示例）；
  2. NIST SP 800-38A F.1.1（ECB）与 F.2.1（CBC）官方向量；
  3. 与 pycryptodome 随机对照（固定种子，覆盖三种密钥长度与多种数据长度）。
说明：不以"加密后再解密"作为正确性依据，往返测试只作为补充。
"""

import random
import unittest

from mitmlab.crypto import aes

try:
    from Crypto.Cipher import AES as PyAES
    from Crypto.Util.Padding import pad as py_pad
    HAVE_PYCRYPTODOME = True
except ImportError:
    HAVE_PYCRYPTODOME = False

H = bytes.fromhex

# FIPS 197 附录 C：明文 00112233...ff，密钥 000102...
FIPS197_C = [
    (H("000102030405060708090a0b0c0d0e0f"), H("69c4e0d86a7b0430d8cdb78070b4c55a")),
    (H("000102030405060708090a0b0c0d0e0f1011121314151617"), H("dda97ca4864cdfe06eaf70a0ec0d7191")),
    (H("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
     H("8ea2b7ca516745bfeafc49904b496089")),
]
FIPS197_C_PLAIN = H("00112233445566778899aabbccddeeff")

SP800_KEY = H("2b7e151628aed2a6abf7158809cf4f3c")
SP800_IV = H("000102030405060708090a0b0c0d0e0f")
SP800_PLAIN = H("6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51"
                "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710")
SP800_ECB = H("3ad77bb40d7a3660a89ecaf32466ef97" "f5d3d58503b9699de785895a96fdbaaf"
              "43b1cd7f598ece23881b00e3ed030688" "7b0c785e27e8ad3f8223207104725dd4")
SP800_CBC = H("7649abac8119b246cee98e9b12e9197d" "5086cb9b507219ee95db113a917678b2"
              "73bed6b8e3c1743b7116e69e22229516" "3ff1caa1681fac09120eca307586e1a7")


class AesBlockVectors(unittest.TestCase):
    def test_fips197_appendix_b(self):
        cipher = aes.AES(SP800_KEY)
        pt = H("3243f6a8885a308d313198a2e0370734")
        ct = H("3925841d02dc09fbdc118597196a0b32")
        self.assertEqual(cipher.encrypt_block(pt), ct)
        self.assertEqual(cipher.decrypt_block(ct), pt)

    def test_fips197_appendix_c_all_key_sizes(self):
        for key, ct in FIPS197_C:
            with self.subTest(key_bits=len(key) * 8):
                cipher = aes.AES(key)
                self.assertEqual(cipher.encrypt_block(FIPS197_C_PLAIN), ct)
                self.assertEqual(cipher.decrypt_block(ct), FIPS197_C_PLAIN)

    def test_key_expansion_fips197_a1(self):
        rks = aes.expand_key(SP800_KEY)
        self.assertEqual(len(rks), 11)
        self.assertEqual(bytes(rks[1]), H("a0fafe1788542cb123a339392a6c7605"))
        self.assertEqual(bytes(rks[10]), H("d014f9a8c9ee2589e13f0cc8b6630ca6"))

    def test_sbox_known_values(self):
        # FIPS 197 图 7：S(00)=63, S(53)=ed, S(ff)=16；且 S 盒是一个置换
        self.assertEqual(aes.SBOX[0x00], 0x63)
        self.assertEqual(aes.SBOX[0x53], 0xED)
        self.assertEqual(aes.SBOX[0xFF], 0x16)
        self.assertEqual(sorted(aes.SBOX), list(range(256)))
        for x in range(256):
            self.assertEqual(aes.INV_SBOX[aes.SBOX[x]], x)

    def test_gf_multiplication_fips197_example(self):
        # FIPS 197 第 4.2 节：{57} • {83} = {c1}
        self.assertEqual(aes._gmul(0x57, 0x83), 0xC1)

    def test_invalid_sizes(self):
        with self.assertRaises(ValueError):
            aes.AES(b"short")
        with self.assertRaises(ValueError):
            aes.AES(bytes(16)).encrypt_block(b"1234")


class AesModeVectors(unittest.TestCase):
    def test_sp800_38a_ecb(self):
        self.assertEqual(aes.ecb_encrypt(SP800_KEY, SP800_PLAIN), SP800_ECB)
        self.assertEqual(aes.ecb_decrypt(SP800_KEY, SP800_ECB), SP800_PLAIN)

    def test_sp800_38a_cbc(self):
        self.assertEqual(aes.cbc_encrypt_raw(SP800_KEY, SP800_IV, SP800_PLAIN), SP800_CBC)
        self.assertEqual(aes.cbc_decrypt_raw(SP800_KEY, SP800_IV, SP800_CBC), SP800_PLAIN)

    def test_cbc_with_padding_prefix_matches_sp800(self):
        # 带 PKCS#7 时，前 4 个密文块应与 SP800-38A 一致，后面多出一个纯填充块
        ct = aes.cbc_encrypt(SP800_KEY, SP800_IV, SP800_PLAIN)
        self.assertEqual(len(ct), 80)
        self.assertEqual(ct[:64], SP800_CBC)
        self.assertEqual(aes.cbc_decrypt(SP800_KEY, SP800_IV, ct), SP800_PLAIN)


class Pkcs7Tests(unittest.TestCase):
    def test_padding_lengths_and_values(self):
        self.assertEqual(aes.pkcs7_pad(b""), b"\x10" * 16)
        self.assertEqual(aes.pkcs7_pad(b"abc"), b"abc" + b"\x0d" * 13)
        self.assertEqual(aes.pkcs7_pad(b"a" * 15), b"a" * 15 + b"\x01")
        self.assertEqual(aes.pkcs7_pad(b"a" * 16), b"a" * 16 + b"\x10" * 16)

    def test_unpad_roundtrip(self):
        for n in range(0, 50):
            data = bytes(range(n))
            self.assertEqual(aes.pkcs7_unpad(aes.pkcs7_pad(data)), data)

    def test_invalid_padding_rejected(self):
        bad = [b"", b"a" * 15, b"a" * 15 + b"\x00", b"a" * 15 + b"\x11",
               b"a" * 14 + b"\x01\x02", b"a" * 16]
        for data in bad:
            with self.subTest(data=data), self.assertRaises(ValueError):
                aes.pkcs7_unpad(data)


@unittest.skipUnless(HAVE_PYCRYPTODOME, "需要 pycryptodome 做库对照")
class AesAgainstPycryptodome(unittest.TestCase):
    def test_random_ecb_and_cbc(self):
        rng = random.Random(197)
        for _ in range(150):
            key = rng.randbytes(rng.choice([16, 24, 32]))
            iv = rng.randbytes(16)
            data = rng.randbytes(rng.randint(0, 200))
            with self.subTest(keylen=len(key), datalen=len(data)):
                expect = PyAES.new(key, PyAES.MODE_CBC, iv).encrypt(py_pad(data, 16))
                self.assertEqual(aes.cbc_encrypt(key, iv, data), expect)
                self.assertEqual(aes.cbc_decrypt(key, iv, expect), data)
                blocks = py_pad(data, 16)
                self.assertEqual(aes.ecb_encrypt(key, blocks),
                                 PyAES.new(key, PyAES.MODE_ECB).encrypt(blocks))

    def test_decrypt_library_ciphertext(self):
        # 用库加密、自实现解密，避免"自加自解"的盲区
        key, iv = bytes(range(16)), bytes(range(16, 32))
        msg = "中间人攻击与防御".encode("utf-8") * 5
        ct = PyAES.new(key, PyAES.MODE_CBC, iv).encrypt(py_pad(msg, 16))
        self.assertEqual(aes.cbc_decrypt(key, iv, ct), msg)


class CbcBehaviour(unittest.TestCase):
    def test_bit_flip_in_ciphertext_changes_next_plaintext_block(self):
        # CBC 的可塑性：翻转第 i 块密文的某一位，会使第 i+1 块明文对应位翻转——
        # 这正是协议中必须加 HMAC 的原因，也是位翻转攻击的原理
        key, iv = SP800_KEY, SP800_IV
        pt = b"A" * 16 + b"transfer 100 yuan" + b"!" * 13  # 3 个明文块 + 填充
        ct = bytearray(aes.cbc_encrypt(key, iv, pt))
        ct[0] ^= 0x01
        res = aes.cbc_decrypt_raw(key, iv, bytes(ct))
        self.assertEqual(res[16:32], bytes([pt[16] ^ 0x01]) + pt[17:32])  # 第 2 块恰好对应位翻转
        self.assertNotEqual(res[:16], pt[:16])                            # 第 1 块被彻底破坏

    def test_bad_arguments(self):
        with self.assertRaises(ValueError):
            aes.cbc_encrypt_raw(SP800_KEY, b"short", bytes(16))
        with self.assertRaises(ValueError):
            aes.cbc_decrypt(SP800_KEY, SP800_IV, b"x" * 15)


if __name__ == "__main__":
    unittest.main()
