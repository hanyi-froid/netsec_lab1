"""认证 DH 握手（STS 风格）的纯协议逻辑，不涉及网络，供 Party 与 Evil 共用。

流程：
    A → B : KEX_INIT  { dh_pub = g^a, nonce_a, [sig_a] }
    B → A : KEX_REPLY { dh_pub = g^b, nonce_b, [sig_b] }
    双方 K = (对方公钥)^(己方私钥) mod p，再经 HKDF 得到会话密钥。

启用 auth_kex 时，签名绑定了身份与整个交换：
    sig_a = Sign_A( "INIT"  ‖ A ‖ B ‖ g^a ‖ nonce_a )
    sig_b = Sign_B( "REPLY" ‖ B ‖ A ‖ g^b ‖ nonce_b ‖ g^a ‖ nonce_a )
B 的签名覆盖了 A 的 DH 公钥与 nonce，所以 Evil 既不能替换 DH 公钥（签名失效），
也不能拿旧会话里的合法应答重放（nonce_a 不同）。对方 RSA 公钥通过 trust 预置，
相当于 CA 证书 / 线下交换的信任根；没有它，签名只是"自己给自己盖章"。
"""

import secrets
from dataclasses import dataclass

from ..crypto import dh, rsa
from ..crypto.numtheory import bytes_to_int
from .messages import KEX_INIT, KEX_REPLY, Message
from .session import SessionKeys, derive_session_keys

NONCE_LEN = 16


class HandshakeError(Exception):
    """握手报文校验失败（格式、公钥合法性或签名）。"""


@dataclass
class HsState:
    """本方握手临时状态：DH 私钥 x、公钥 y（定长字节）、nonce。"""
    x: int
    y: bytes
    nonce: bytes


def _lp(b: bytes) -> bytes:
    """长度前缀编码，保证拼接后的签名原文无歧义。"""
    return len(b).to_bytes(2, "big") + b


def init_transcript(sender: str, receiver: str, y: bytes, nonce: bytes) -> bytes:
    return b"MITMLAB-KEX-INIT" + _lp(sender.encode()) + _lp(receiver.encode()) + _lp(y) + _lp(nonce)


def reply_transcript(sender: str, receiver: str, y: bytes, nonce: bytes,
                     peer_y: bytes, peer_nonce: bytes) -> bytes:
    return (b"MITMLAB-KEX-REPLY" + _lp(sender.encode()) + _lp(receiver.encode())
            + _lp(y) + _lp(nonce) + _lp(peer_y) + _lp(peer_nonce))


def _new_state(group: dh.DHGroup) -> HsState:
    x, y = dh.generate_keypair(group)
    return HsState(x, dh.public_to_bytes(y, group), secrets.token_bytes(NONCE_LEN))


def build_init(sender: str, receiver: str, signer=None, group: dh.DHGroup = dh.GROUP_1536):
    """构造 KEX_INIT。signer 为 RSA 私钥时附加签名。返回 (报文, 本方状态)。"""
    st = _new_state(group)
    fields = {"dh_pub": st.y, "nonce": st.nonce}
    if signer is not None:
        fields["sig"] = rsa.sign(signer, init_transcript(sender, receiver, st.y, st.nonce))
    return Message(KEX_INIT, sender, receiver, fields), st


def build_reply(sender: str, receiver: str, peer_y: bytes, peer_nonce: bytes, signer=None,
                group: dh.DHGroup = dh.GROUP_1536):
    """构造 KEX_REPLY（应答 peer_y/peer_nonce）。返回 (报文, 本方状态)。"""
    st = _new_state(group)
    fields = {"dh_pub": st.y, "nonce": st.nonce}
    if signer is not None:
        fields["sig"] = rsa.sign(
            signer, reply_transcript(sender, receiver, st.y, st.nonce, peer_y, peer_nonce))
    return Message(KEX_REPLY, sender, receiver, fields), st


def _common_checks(msg: Message, msg_type: str, own: str, expected_peer: str, group: dh.DHGroup):
    """公共校验：类型、收发方名称、字段格式、DH 公钥合法性。返回 (y_bytes, nonce)。"""
    if msg.type != msg_type:
        raise HandshakeError(f"期望 {msg_type}，收到 {msg.type}")
    if msg.receiver != own or msg.sender != expected_peer:
        raise HandshakeError(f"报文声明的收发方 {msg.sender}→{msg.receiver} 与预期不符")
    y, nonce = msg.fields.get("dh_pub"), msg.fields.get("nonce")
    if (not isinstance(y, bytes) or len(y) != group.byte_len
            or not isinstance(nonce, bytes) or len(nonce) != NONCE_LEN):
        raise HandshakeError("dh_pub / nonce 缺失或长度非法")
    try:
        dh.validate_public(bytes_to_int(y), group)
    except dh.InvalidPublicKey as exc:
        raise HandshakeError(f"DH 公钥非法: {exc}") from exc
    return y, nonce


def _check_signature(msg: Message, transcript: bytes, trusted_key) -> None:
    sig = msg.fields.get("sig")
    if not isinstance(sig, bytes) or not rsa.verify(trusted_key, transcript, sig):
        raise HandshakeError(f"签名验证失败：该报文不是 {msg.sender} 签发的，或内容已被替换")


def process_init(msg: Message, own: str, expected_peer: str, trusted_key=None,
                 group: dh.DHGroup = dh.GROUP_1536):
    """应答方处理 KEX_INIT。trusted_key 非空则要求并验证签名。返回 (y_bytes, nonce)。"""
    y, nonce = _common_checks(msg, KEX_INIT, own, expected_peer, group)
    if trusted_key is not None:
        _check_signature(msg, init_transcript(msg.sender, msg.receiver, y, nonce), trusted_key)
    return y, nonce


def process_reply(msg: Message, own: str, expected_peer: str, my_state: HsState,
                  trusted_key=None, group: dh.DHGroup = dh.GROUP_1536):
    """发起方处理 KEX_REPLY。验签时把"自己发出的 y/nonce"重新放进签名原文。"""
    y, nonce = _common_checks(msg, KEX_REPLY, own, expected_peer, group)
    if trusted_key is not None:
        _check_signature(
            msg, reply_transcript(msg.sender, msg.receiver, y, nonce, my_state.y, my_state.nonce),
            trusted_key)
    return y, nonce


def derive_keys(my_state: HsState, peer_y: bytes, nonce_a: bytes, nonce_b: bytes,
                group: dh.DHGroup = dh.GROUP_1536) -> SessionKeys:
    """计算 DH 共享秘密并派生会话密钥（nonce_a 为发起方 nonce，nonce_b 为应答方 nonce）。"""
    shared = dh.shared_secret(my_state.x, bytes_to_int(peer_y), group)
    return derive_session_keys(shared, nonce_a, nonce_b)
