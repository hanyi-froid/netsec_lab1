"""SHA-256 杂凑算法（FIPS 180-4）的纯 Python 实现，支持增量更新。

流程：消息补位（0x80 + 零填充 + 64 位大端比特长度）→ 按 512 位分组 →
每组做 64 轮压缩（消息扩展 W[t]、逻辑函数 Ch/Maj/Σ/σ、常数 K[t]）。
"""

import struct

_MASK = 0xFFFFFFFF

# 初始哈希值：前 8 个素数平方根小数部分的前 32 位
_H0 = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)

# 轮常数：前 64 个素数立方根小数部分的前 32 位
_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)

BLOCK_SIZE = 64   # 分组长度（字节），HMAC 用到
DIGEST_SIZE = 32  # 摘要长度（字节）


def _rotr(x: int, n: int) -> int:
    """32 位循环右移。"""
    return ((x >> n) | (x << (32 - n))) & _MASK


class SHA256:
    """SHA-256 对象，接口仿照 hashlib：update / digest / hexdigest / copy。"""

    block_size = BLOCK_SIZE
    digest_size = DIGEST_SIZE

    def __init__(self, data: bytes = b""):
        self._h = list(_H0)
        self._buf = b""   # 尚未凑满一个分组的残余数据
        self._len = 0     # 已处理的总字节数
        if data:
            self.update(data)

    def _compress(self, block: bytes) -> None:
        """对一个 64 字节分组执行 64 轮压缩，更新内部状态。"""
        w = list(struct.unpack(">16I", block))
        for t in range(16, 64):
            s0 = _rotr(w[t - 15], 7) ^ _rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
            s1 = _rotr(w[t - 2], 17) ^ _rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
            w.append((w[t - 16] + s0 + w[t - 7] + s1) & _MASK)

        a, b, c, d, e, f, g, h = self._h
        for t in range(64):
            big_s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ (~e & _MASK & g)
            t1 = (h + big_s1 + ch + _K[t] + w[t]) & _MASK
            big_s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (big_s0 + maj) & _MASK
            h, g, f, e, d, c, b, a = g, f, e, (d + t1) & _MASK, c, b, a, (t1 + t2) & _MASK

        self._h = [(x + y) & _MASK for x, y in zip(self._h, (a, b, c, d, e, f, g, h))]

    def update(self, data: bytes) -> "SHA256":
        """追加数据，可多次调用。"""
        data = bytes(data)
        self._len += len(data)
        buf = self._buf + data
        full = len(buf) - len(buf) % BLOCK_SIZE
        for i in range(0, full, BLOCK_SIZE):
            self._compress(buf[i:i + BLOCK_SIZE])
        self._buf = buf[full:]
        return self

    def copy(self) -> "SHA256":
        """复制当前状态（HMAC 中用于复用预计算的 ipad/opad 状态）。"""
        other = SHA256()
        other._h = list(self._h)
        other._buf = self._buf
        other._len = self._len
        return other

    def digest(self) -> bytes:
        """返回摘要。不改变当前对象状态，之后仍可继续 update。"""
        clone = self.copy()
        # 补位：0x80，然后补零到 56 (mod 64)，最后 8 字节为消息比特长度
        pad_len = (55 - self._len) % 64
        clone.update(b"\x80" + b"\x00" * pad_len + struct.pack(">Q", self._len * 8))
        return struct.pack(">8I", *clone._h)

    def hexdigest(self) -> str:
        return self.digest().hex()


def sha256(data: bytes) -> bytes:
    """一次性计算 SHA-256 摘要。"""
    return SHA256(data).digest()
