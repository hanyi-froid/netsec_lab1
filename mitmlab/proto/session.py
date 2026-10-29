"""会话层：密钥派生与数据包的"加密 + 认证"封装。

密钥派生：HKDF-SHA256(DH 共享秘密, salt=nonceA‖nonceB) 一次性导出 4 把独立密钥——
A→B、B→A 两个方向各一把 AES-128 加密密钥和一把 HMAC 密钥。方向分离可以防止
Evil 把 Alice 的报文原样"反射"回 Alice。

数据包采用 Encrypt-then-MAC：
    ct  = AES-128-CBC(k_enc, iv, PKCS7(plaintext))
    mac = HMAC-SHA256(k_mac, 方向标签 ‖ seq ‖ iv ‖ ct)
接收方先验 MAC（常数时间比较）再解密，避免对未认证密文做填充校验；
seq 被 MAC 覆盖，因而攻击者无法修改序号来绕过重放检测。
"""

import secrets
from dataclasses import dataclass

from ..crypto import aes
from ..crypto.hmac_hkdf import constant_time_equal, hkdf, hmac_sha256
from ..crypto.sha256 import sha256
from .profiles import SecurityProfile

KDF_INFO = b"mitmlab-v1 session keys"
_DIR_A2B, _DIR_B2A = b"A2B", b"B2A"


class SessionError(Exception):
    """数据包处理失败的基类。"""


class MalformedError(SessionError):
    """缺字段或字段类型/长度非法。"""


class IntegrityError(SessionError):
    """MAC 校验失败：报文被篡改，或密钥不一致。"""


class ReplayError(SessionError):
    """序号不大于已接收的最大序号：重放或乱序。"""


class DecryptError(SessionError):
    """解密或去填充失败。"""


@dataclass(frozen=True)
class SessionKeys:
    a2b_enc: bytes
    a2b_mac: bytes
    b2a_enc: bytes
    b2a_mac: bytes

    def fingerprint(self) -> str:
        """密钥指纹（取密钥材料哈希的前 6 字节），界面用于比较各方持有的密钥是否一致。"""
        return sha256(self.a2b_enc + self.b2a_enc + self.a2b_mac + self.b2a_mac).hex()[:12]


def derive_session_keys(shared_secret: bytes, nonce_a: bytes, nonce_b: bytes) -> SessionKeys:
    """由 DH 共享秘密与双方 nonce 派生 4 把方向独立的会话密钥。"""
    okm = hkdf(shared_secret, 96, salt=nonce_a + nonce_b, info=KDF_INFO)
    return SessionKeys(okm[0:16], okm[16:48], okm[48:64], okm[64:96])


class Session:
    """一方持有的会话状态。role 为 'A'（握手发起方）或 'B'（应答方）。"""

    def __init__(self, keys: SessionKeys, role: str, profile: SecurityProfile):
        if role not in ("A", "B"):
            raise ValueError("role 必须是 'A' 或 'B'")
        self.keys, self.role, self.profile = keys, role, profile
        self._send_seq = 0
        self._recv_max = 0
        if role == "A":
            self._tx = (keys.a2b_enc, keys.a2b_mac, _DIR_A2B)
            self._rx = (keys.b2a_enc, keys.b2a_mac, _DIR_B2A)
        else:
            self._tx = (keys.b2a_enc, keys.b2a_mac, _DIR_B2A)
            self._rx = (keys.a2b_enc, keys.a2b_mac, _DIR_A2B)

    @staticmethod
    def _mac(mac_key: bytes, label: bytes, seq: int, iv: bytes, ct: bytes) -> bytes:
        return hmac_sha256(mac_key, label + seq.to_bytes(8, "big") + iv + ct)

    def seal(self, plaintext: bytes) -> dict:
        """加密并认证一条明文，返回报文 fields：seq / iv / ct / mac（未启用 MAC 时 mac 为空）。"""
        enc_key, mac_key, label = self._tx
        self._send_seq += 1
        iv = secrets.token_bytes(16)
        ct = aes.cbc_encrypt(enc_key, iv, plaintext)
        mac = self._mac(mac_key, label, self._send_seq, iv, ct) if self.profile.mac else b""
        return {"seq": self._send_seq, "iv": iv, "ct": ct, "mac": mac}

    def open(self, fields: dict) -> bytes:
        """校验并解密收到的数据包，失败抛出 SessionError 的子类。"""
        enc_key, mac_key, label = self._rx
        seq, iv, ct, mac = (fields.get(k) for k in ("seq", "iv", "ct", "mac"))
        if (not isinstance(seq, int) or isinstance(seq, bool) or seq < 1 or seq >= 1 << 63
                or not isinstance(iv, bytes) or len(iv) != 16
                or not isinstance(ct, bytes) or not ct or len(ct) % 16
                or not isinstance(mac, bytes)):
            raise MalformedError("数据包字段缺失或格式非法")
        if self.profile.mac:
            if not constant_time_equal(mac, self._mac(mac_key, label, seq, iv, ct)):
                raise IntegrityError("MAC 校验失败")
        if self.profile.anti_replay and seq <= self._recv_max:
            raise ReplayError(f"序号 {seq} 已过期（已收到的最大序号为 {self._recv_max}）")
        try:
            plaintext = aes.cbc_decrypt(enc_key, iv, ct)
        except ValueError as exc:
            raise DecryptError(str(exc)) from exc
        self._recv_max = max(self._recv_max, seq)
        return plaintext
