"""SHA-256 单元测试。

依据：
  1. FIPS 180-4 / NIST CAVP（SHA-256 ShortMsg 示例）官方标准向量；
  2. 分组边界长度（55/56/63/64/65 字节）与增量更新一致性；
  3. 与标准库 hashlib 对照（hashlib 只在测试中使用）。
"""

import hashlib
import random
import unittest

from mitmlab.crypto.sha256 import SHA256, sha256

# (消息, 期望摘要)：来自 FIPS 180-2 附录 / NIST 示例
STANDARD_VECTORS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
]


class Sha256StandardVectors(unittest.TestCase):
    def test_nist_vectors(self):
        for msg, expected in STANDARD_VECTORS:
            with self.subTest(msg=msg[:20]):
                self.assertEqual(sha256(msg).hex(), expected)

    def test_one_million_a(self):
        # FIPS 180-2 长消息向量：一百万个 'a'
        h = SHA256()
        chunk = b"a" * 1000
        for _ in range(1000):
            h.update(chunk)
        self.assertEqual(
            h.hexdigest(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")


class Sha256Boundaries(unittest.TestCase):
    def test_padding_boundaries_match_hashlib(self):
        # 55 字节恰好放得下 0x80+长度；56 字节需要多一个分组，是补位逻辑的易错点
        for n in list(range(0, 130)) + [255, 256, 257, 1023, 1024, 1025]:
            data = bytes((i * 7 + 3) & 0xFF for i in range(n))
            with self.subTest(n=n):
                self.assertEqual(sha256(data), hashlib.sha256(data).digest())

    def test_random_messages_match_hashlib(self):
        rng = random.Random(20261028)
        for _ in range(200):
            data = rng.randbytes(rng.randint(0, 600))
            self.assertEqual(sha256(data), hashlib.sha256(data).digest())

    def test_incremental_update_equals_one_shot(self):
        rng = random.Random(1)
        data = rng.randbytes(1000)
        h = SHA256()
        pos = 0
        while pos < len(data):
            step = rng.randint(1, 97)
            h.update(data[pos:pos + step])
            pos += step
        self.assertEqual(h.digest(), hashlib.sha256(data).digest())

    def test_digest_does_not_mutate_state(self):
        h = SHA256(b"hello")
        first = h.digest()
        self.assertEqual(h.digest(), first)
        h.update(b" world")
        self.assertEqual(h.digest(), hashlib.sha256(b"hello world").digest())

    def test_copy_is_independent(self):
        h = SHA256(b"abc")
        c = h.copy()
        c.update(b"def")
        self.assertEqual(h.digest(), hashlib.sha256(b"abc").digest())
        self.assertEqual(c.digest(), hashlib.sha256(b"abcdef").digest())

    def test_digest_length(self):
        self.assertEqual(len(sha256(b"x")), 32)


if __name__ == "__main__":
    unittest.main()
