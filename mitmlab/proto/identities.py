"""角色身份与密钥：每个角色一把 RSA 密钥，对方公钥通过"信任库"预置。"""

from dataclasses import dataclass
from functools import lru_cache

from ..crypto import rsa

ROLE_NAMES = ("Alice", "Bob", "Evil")


@dataclass(frozen=True)
class KeyRing:
    """三个角色的 RSA 密钥对。真实场景中 Alice/Bob 的公钥由 CA 证书或线下指纹核对得到。"""
    alice: rsa.RSAPrivateKey
    bob: rsa.RSAPrivateKey
    evil: rsa.RSAPrivateKey

    def trust_for(self, name: str) -> dict:
        """某角色预置的信任库：Alice 只信任 Bob 的公钥，Bob 只信任 Alice 的公钥。"""
        return {"Alice": {"Bob": self.bob.public}, "Bob": {"Alice": self.alice.public}}.get(name, {})


def generate_keyring(bits: int = 2048) -> KeyRing:
    """生成一套新密钥（纯 Python 生成 2048 位 RSA 约需数百毫秒到数秒）。"""
    return KeyRing(*(rsa.generate_keypair(bits) for _ in ROLE_NAMES))


@lru_cache(maxsize=None)
def default_keyring(bits: int = 2048) -> KeyRing:
    """进程内缓存的密钥环，同一进程多次运行场景时复用，避免重复生成。"""
    return generate_keyring(bits)
