"""数论工具单元测试：模幂、扩展欧几里得、模逆、Miller-Rabin、素数生成。

依据：
  1. 与 Python 内置 pow(x, e, m) / pow(x, -1, m) 对照（内置函数只在测试中使用）；
  2. 已知素数（梅森素数）与 Carmichael 数、强伪素数等经典合数用例；
  3. 小范围内与试除法的全量对照；
  4. 若安装了 pycryptodome，则与其 isPrime 对照。
"""

import random
import unittest

from mitmlab.crypto import numtheory as nt

try:
    from Crypto.Util.number import isPrime as pycrypto_is_prime
    HAVE_PYCRYPTODOME = True
except ImportError:
    HAVE_PYCRYPTODOME = False

# Carmichael 数：满足费马小定理却是合数，Fermat 检测会被骗，Miller-Rabin 不会
CARMICHAEL = [561, 1105, 1729, 2465, 2821, 6601, 8911, 41041, 825265, 321197185]
# 以 2 为底的强伪素数；3215031751 同时是底 2,3,5,7 的强伪素数
STRONG_PSEUDOPRIMES = [2047, 3277, 4033, 4681, 8321, 3215031751]
MERSENNE_PRIMES = [(1 << p) - 1 for p in (31, 61, 89, 107, 127, 521, 607)]


def _trial_division_is_prime(n: int) -> bool:
    if n < 2:
        return False
    i = 2
    while i * i <= n:
        if n % i == 0:
            return False
        i += 1
    return True


class ModExpTests(unittest.TestCase):
    def test_small_cases(self):
        self.assertEqual(nt.mod_exp(2, 10, 1000), 24)
        self.assertEqual(nt.mod_exp(5, 0, 7), 1)
        self.assertEqual(nt.mod_exp(0, 5, 7), 0)
        self.assertEqual(nt.mod_exp(123, 456, 1), 0)

    def test_random_matches_builtin_pow(self):
        rng = random.Random(1)
        for _ in range(300):
            m = rng.getrandbits(rng.choice([8, 64, 256, 1024])) | 1
            b, e = rng.getrandbits(1100), rng.getrandbits(1100)
            self.assertEqual(nt.mod_exp(b, e, m), pow(b, e, m))

    def test_fermat_little_theorem(self):
        p = (1 << 127) - 1
        for a in (2, 3, 12345678901234567890):
            self.assertEqual(nt.mod_exp(a, p - 1, p), 1)

    def test_invalid_arguments(self):
        with self.assertRaises(ValueError):
            nt.mod_exp(2, -1, 7)
        with self.assertRaises(ValueError):
            nt.mod_exp(2, 3, 0)


class EgcdAndInverseTests(unittest.TestCase):
    def test_bezout_identity(self):
        rng = random.Random(2)
        for _ in range(200):
            a, b = rng.getrandbits(200), rng.getrandbits(200)
            g, x, y = nt.egcd(a, b)
            self.assertEqual(a * x + b * y, g)
            self.assertEqual(a % g if g else 0, 0)
            self.assertEqual(b % g if g else 0, 0)

    def test_inverse_matches_builtin(self):
        rng = random.Random(3)
        for _ in range(200):
            m = rng.getrandbits(256) | 1
            a = rng.getrandbits(256)
            try:
                expected = pow(a, -1, m)
            except ValueError:
                with self.assertRaises(ValueError):
                    nt.mod_inv(a, m)
                continue
            self.assertEqual(nt.mod_inv(a, m), expected)
            self.assertEqual(a * nt.mod_inv(a, m) % m, 1)

    def test_known_inverse(self):
        self.assertEqual(nt.mod_inv(3, 11), 4)
        self.assertEqual(nt.mod_inv(17, 3120), 2753)  # 经典 RSA 教科书示例 e=17, phi=3120

    def test_no_inverse_raises(self):
        with self.assertRaises(ValueError):
            nt.mod_inv(6, 9)

    def test_gcd(self):
        self.assertEqual(nt.gcd(48, 18), 6)
        self.assertEqual(nt.gcd(17, 5), 1)


class PrimalityTests(unittest.TestCase):
    def test_exhaustive_below_5000_matches_trial_division(self):
        for n in range(0, 5000):
            self.assertEqual(nt.is_probable_prime(n), _trial_division_is_prime(n), n)

    def test_carmichael_numbers_rejected(self):
        for n in CARMICHAEL:
            self.assertFalse(nt.is_probable_prime(n), n)

    def test_strong_pseudoprimes_rejected(self):
        for n in STRONG_PSEUDOPRIMES:
            self.assertFalse(nt.is_probable_prime(n), n)

    def test_mersenne_primes_accepted(self):
        for n in MERSENNE_PRIMES:
            self.assertTrue(nt.is_probable_prime(n), n)

    def test_product_of_large_primes_rejected(self):
        p, q = (1 << 127) - 1, (1 << 89) - 1
        self.assertFalse(nt.is_probable_prime(p * q))

    @unittest.skipUnless(HAVE_PYCRYPTODOME, "需要 pycryptodome 做库对照")
    def test_random_numbers_match_pycryptodome(self):
        rng = random.Random(4)
        for _ in range(300):
            n = rng.getrandbits(rng.choice([16, 64, 128])) | 1
            self.assertEqual(nt.is_probable_prime(n), bool(pycrypto_is_prime(n)), n)


class PrimeGenerationTests(unittest.TestCase):
    def test_generated_prime_properties(self):
        for bits in (16, 64, 256):
            p = nt.gen_prime(bits)
            self.assertEqual(p.bit_length(), bits)
            self.assertEqual(p & 1, 1)
            self.assertTrue(_trial_division_is_prime(p) if bits <= 32 else nt.is_probable_prime(p))

    def test_two_top_bits_set(self):
        p = nt.gen_prime(128)
        self.assertEqual(p >> 126, 0b11)

    @unittest.skipUnless(HAVE_PYCRYPTODOME, "需要 pycryptodome 做库对照")
    def test_generated_prime_accepted_by_pycryptodome(self):
        for _ in range(5):
            self.assertTrue(pycrypto_is_prime(nt.gen_prime(256)))

    def test_too_small_rejected(self):
        with self.assertRaises(ValueError):
            nt.gen_prime(4)


class HelperTests(unittest.TestCase):
    def test_int_bytes_roundtrip_and_known_value(self):
        self.assertEqual(nt.int_to_bytes(0x0102, 4), b"\x00\x00\x01\x02")
        self.assertEqual(nt.bytes_to_int(b"\x00\x00\x01\x02"), 0x0102)
        with self.assertRaises(ValueError):
            nt.int_to_bytes(256, 1)
        with self.assertRaises(ValueError):
            nt.int_to_bytes(-1, 4)

    def test_rand_range_bounds(self):
        for _ in range(500):
            self.assertTrue(5 <= nt.rand_range(5, 8) <= 8)
        self.assertEqual(nt.rand_range(7, 7), 7)
        with self.assertRaises(ValueError):
            nt.rand_range(3, 2)


if __name__ == "__main__":
    unittest.main()
