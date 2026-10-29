"""Diffie-Hellman 密钥交换（RFC 3526 第 2 节：1536 位 MODP 群，id 5）。

该群的模数 p 是安全素数（p = 2q+1，q 也是素数），生成元 g = 2 生成阶为 q 的子群。
本模块包含公钥合法性校验：拒绝 0、1、p-1、p 及越界值，并检查其属于阶 q 的子群，
防止中间人发送"小子群/退化公钥"把共享秘密强制成已知值。
"""

from dataclasses import dataclass

from .numtheory import bytes_to_int, int_to_bytes, mod_exp, rand_range

# RFC 3526 第 2 节给出的 1536 位素数（十六进制，原文按 32 位一组书写）
_P_1536_HEX = (
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
    "670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF"
)
RFC3526_1536_P = int(_P_1536_HEX.replace(" ", ""), 16)
RFC3526_1536_G = 2


class InvalidPublicKey(ValueError):
    """对端 DH 公钥未通过合法性校验。"""


@dataclass(frozen=True)
class DHGroup:
    """DH 群参数：安全素数 p 与生成元 g。"""
    p: int
    g: int

    @property
    def q(self) -> int:
        """子群阶 (p-1)/2。"""
        return (self.p - 1) // 2

    @property
    def byte_len(self) -> int:
        return (self.p.bit_length() + 7) // 8


GROUP_1536 = DHGroup(RFC3526_1536_P, RFC3526_1536_G)


def generate_private(group: DHGroup = GROUP_1536) -> int:
    """生成私钥 x，取值于 [2, q-1]。"""
    return rand_range(2, group.q - 1)


def public_from_private(x: int, group: DHGroup = GROUP_1536) -> int:
    """计算公钥 y = g^x mod p。"""
    return mod_exp(group.g, x, group.p)


def generate_keypair(group: DHGroup = GROUP_1536):
    """返回 (私钥, 公钥)。"""
    x = generate_private(group)
    return x, public_from_private(x, group)


def validate_public(y: int, group: DHGroup = GROUP_1536) -> None:
    """校验对端公钥，非法时抛 InvalidPublicKey。

    1. 2 <= y <= p-2：排除 0、1（共享秘密恒为 0/1）和 p-1（共享秘密只能是 ±1）；
    2. y^q mod p == 1：要求 y 属于阶为 q 的子群，排除小阶元素。
    """
    if not isinstance(y, int) or y < 2 or y > group.p - 2:
        raise InvalidPublicKey("DH 公钥超出合法范围 [2, p-2]")
    if mod_exp(y, group.q, group.p) != 1:
        raise InvalidPublicKey("DH 公钥不属于素数阶子群")


def shared_secret(x: int, peer_public: int, group: DHGroup = GROUP_1536) -> bytes:
    """计算共享秘密 K = peer^x mod p，返回定长大端字节串（先校验对端公钥）。"""
    validate_public(peer_public, group)
    return int_to_bytes(mod_exp(peer_public, x, group.p), group.byte_len)


def public_to_bytes(y: int, group: DHGroup = GROUP_1536) -> bytes:
    """公钥序列化为定长大端字节串。"""
    return int_to_bytes(y, group.byte_len)


def public_from_bytes(data: bytes) -> int:
    return bytes_to_int(data)
