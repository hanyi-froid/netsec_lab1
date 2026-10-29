"""RSA 密钥生成与 PKCS#1 v1.5 (RFC 8017 RSASSA-PKCS1-v1_5) 数字签名，哈希为 SHA-256。

签名过程：EM = 0x00 || 0x01 || PS(0xFF…) || 0x00 || DigestInfo || SHA256(M)，
其中 DigestInfo 是 SHA-256 的 ASN.1 DER 前缀；签名 s = EM^d mod n。
验证时不去解析 EM，而是用公钥恢复 EM'，与自己重新构造的期望值比较，
避免 Bleichenbacher 式的宽松解析漏洞。
私钥运算使用 CRT 加速，并在输出前用公钥验算以防计算错误。
"""

from dataclasses import dataclass

from .hmac_hkdf import constant_time_equal
from .numtheory import bytes_to_int, gcd, gen_prime, int_to_bytes, mod_exp, mod_inv
from .sha256 import sha256

DEFAULT_E = 65537

# SHA-256 的 DigestInfo DER 前缀（RFC 8017 第 9.2 节注 1）：
#   SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }, OCTET STRING(32) }
SHA256_DIGESTINFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int

    @property
    def byte_len(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def to_dict(self) -> dict:
        """序列化为可 JSON 化的字典（十六进制字符串）。"""
        return {"n": format(self.n, "x"), "e": format(self.e, "x")}

    @staticmethod
    def from_dict(d: dict) -> "RSAPublicKey":
        return RSAPublicKey(int(d["n"], 16), int(d["e"], 16))

    def fingerprint(self) -> str:
        """公钥指纹：SHA-256(n||e) 的前 8 字节十六进制，便于界面展示与带外比对。"""
        n_bytes = int_to_bytes(self.n, self.byte_len)
        return sha256(n_bytes + int_to_bytes(self.e, 4)).hex()[:16]


@dataclass(frozen=True)
class RSAPrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int

    @property
    def public(self) -> RSAPublicKey:
        return RSAPublicKey(self.n, self.e)

    def to_dict(self) -> dict:
        return {k: format(getattr(self, k), "x") for k in ("n", "e", "d", "p", "q")}

    @staticmethod
    def from_dict(d: dict) -> "RSAPrivateKey":
        return RSAPrivateKey(*(int(d[k], 16) for k in ("n", "e", "d", "p", "q")))


def key_from_primes(p: int, q: int, e: int = DEFAULT_E) -> RSAPrivateKey:
    """由给定素数 p、q 构造密钥对（测试中用于确定性对照）。"""
    if p == q:
        raise ValueError("p 与 q 不能相同")
    lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)  # Carmichael 函数 λ(n)
    if gcd(e, lam) != 1:
        raise ValueError("e 与 λ(n) 不互素")
    return RSAPrivateKey(p * q, e, mod_inv(e, lam), p, q)


def generate_keypair(bits: int = 2048, e: int = DEFAULT_E) -> RSAPrivateKey:
    """生成 RSA 密钥对。p、q 各 bits/2 位，且 n 恰为 bits 位。"""
    if bits < 512 or bits % 2:
        raise ValueError("密钥位数须为不小于 512 的偶数")
    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits // 2)
        if p == q or abs(p - q).bit_length() < bits // 2 - 10:
            continue  # 过于接近的 p、q 可被费马分解法攻破
        if gcd(e, p - 1) != 1 or gcd(e, q - 1) != 1:
            continue
        key = key_from_primes(p, q, e)
        if key.n.bit_length() == bits:
            return key


def _private_op(key: RSAPrivateKey, m: int) -> int:
    """RSA 私钥运算 m^d mod n，使用中国剩余定理加速并验算结果。"""
    dp, dq = key.d % (key.p - 1), key.d % (key.q - 1)
    qinv = mod_inv(key.q, key.p)
    m1, m2 = mod_exp(m % key.p, dp, key.p), mod_exp(m % key.q, dq, key.q)
    h = (qinv * (m1 - m2)) % key.p
    s = m2 + h * key.q
    if mod_exp(s, key.e, key.n) != m % key.n:  # 防止计算错误泄露私钥
        raise ArithmeticError("RSA 私钥运算自检失败")
    return s


def emsa_pkcs1_v15_encode(message: bytes, em_len: int) -> bytes:
    """EMSA-PKCS1-v1_5 编码（哈希为 SHA-256）。"""
    t = SHA256_DIGESTINFO_PREFIX + sha256(message)
    if em_len < len(t) + 11:
        raise ValueError("密钥过短，无法编码")
    return b"\x00\x01" + b"\xff" * (em_len - len(t) - 3) + b"\x00" + t


def sign(key: RSAPrivateKey, message: bytes) -> bytes:
    """RSASSA-PKCS1-v1_5 签名，返回与模数等长的签名字节串。"""
    k = (key.n.bit_length() + 7) // 8
    em = emsa_pkcs1_v15_encode(message, k)
    return int_to_bytes(_private_op(key, bytes_to_int(em)), k)


def verify(key: RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """验证签名，通过返回 True，任何异常或不匹配均返回 False。"""
    k = key.byte_len
    if len(signature) != k:
        return False
    s = bytes_to_int(signature)
    if s >= key.n:
        return False
    try:
        em = int_to_bytes(mod_exp(s, key.e, key.n), k)
        expected = emsa_pkcs1_v15_encode(message, k)
    except ValueError:
        return False
    return constant_time_equal(em, expected)
