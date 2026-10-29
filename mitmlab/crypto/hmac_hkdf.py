"""HMAC-SHA256（RFC 2104 / FIPS 198-1）与 HKDF-SHA256（RFC 5869）。

HMAC 用于报文完整性保护（防篡改、防位翻转）；HKDF 用于把 DH 共享秘密派生为
独立的加密密钥与 MAC 密钥，避免直接拿 DH 原始输出当对称密钥。
"""

from .sha256 import SHA256, BLOCK_SIZE, DIGEST_SIZE, sha256


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA256：H((K' xor opad) || H((K' xor ipad) || msg))。"""
    if len(key) > BLOCK_SIZE:
        key = sha256(key)            # 过长的密钥先哈希
    key = key.ljust(BLOCK_SIZE, b"\x00")  # 不足分组长度则补零
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    inner = SHA256(ipad).update(msg).digest()
    return SHA256(opad).update(inner).digest()


def constant_time_equal(a: bytes, b: bytes) -> bool:
    """常数时间比较，避免通过比较耗时泄露 MAC 的匹配前缀长度。"""
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract：PRK = HMAC(salt, IKM)；salt 为空时用全零串。"""
    if not salt:
        salt = b"\x00" * DIGEST_SIZE
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand：T(i) = HMAC(PRK, T(i-1) || info || i)，拼接后截取 length 字节。"""
    if length > 255 * DIGEST_SIZE:
        raise ValueError("请求的输出过长")
    okm, t, counter = b"", b"", 1
    while len(okm) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        okm += t
        counter += 1
    return okm[:length]


def hkdf(ikm: bytes, length: int, salt: bytes = b"", info: bytes = b"") -> bytes:
    """完整 HKDF（Extract-then-Expand）。"""
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)
