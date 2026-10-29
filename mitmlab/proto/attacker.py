"""中间人 Evil：位于 Alice 与 Bob 之间的网关，按所选模式窃听、篡改、冒充、重放。

Evil 与普通通信方一样只能看到线路上的 bytes。它不拥有 Alice/Bob 的任何私钥：
    PASSIVE      被动窃听：只转发并记录，没有会话密钥所以读不到明文
    MITM         DH 密钥替换：分别与 Alice、Bob 完成两次握手，持有两把会话密钥，
                 解密、（可选）篡改、再用另一把密钥重新加密转发
    IMPERSONATE  冒充 Bob：截获 Alice 的握手并自己扮演 Bob，不转发给真正的 Bob
    BITFLIP      不知道密钥也能翻转 CBC 密文的某一位（利用 CBC 可塑性）
    REPLAY       记录 Alice→Bob 的合法数据包，稍后原样重发
当启用 auth_kex 时，Evil 用自己的 RSA 密钥伪造签名，因为没有 Alice/Bob 的私钥，验签必然失败。
"""

from enum import Enum
from typing import Callable, Optional

from . import events as ev
from .channel import Delivery, Network
from .handshake import HandshakeError, build_init, build_reply, derive_keys
from .messages import DATA, KEX_INIT, KEX_REPLY, Message, WireError, decode, decode_text, describe, encode
from .profiles import SecurityProfile
from .roles import Endpoint
from .session import Session, SessionError

ALICE, BOB = "Alice", "Bob"


class EvilMode(str, Enum):
    PASSIVE = "passive"
    MITM = "mitm"
    IMPERSONATE = "impersonate"
    BITFLIP = "bitflip"
    REPLAY = "replay"


MODE_LABELS = {
    EvilMode.PASSIVE: "被动窃听（仅转发）",
    EvilMode.MITM: "DH 密钥替换（窃听 + 篡改）",
    EvilMode.IMPERSONATE: "冒充 Bob",
    EvilMode.BITFLIP: "密文位翻转篡改",
    EvilMode.REPLAY: "重放数据包",
}

IMPERSONATOR_REPLY = "（Evil 冒充 Bob）已收到，我会处理。"


class Evil(Endpoint):
    def __init__(self, network: Network, log: ev.EventLog, profile: SecurityProfile, own_key,
                 mode: EvilMode = EvilMode.PASSIVE,
                 tamper: Optional[Callable[[str], str]] = None):
        super().__init__("Evil", network, log)
        self.profile, self.mode, self.tamper = profile, mode, tamper
        self._key = own_key
        self.spied: list = []        # (方向, 窃听到的明文)
        self.tampered: list = []     # (原文, 篡改后)
        self.captured: list = []     # (方向, 原始数据包 bytes)，供重放
        self.sessions: dict = {}     # 'Alice' / 'Bob' -> Evil 与该方建立的会话
        self._hs_bob = None          # Evil 以"Alice"身份向 Bob 发起握手的状态
        self._alice_hello = None     # Alice 的 (dh_pub, nonce)
        self._replayed = False

    @property
    def key_fingerprints(self) -> dict:
        return {who: s.keys.fingerprint() for who, s in self.sessions.items()}

    def _signer(self):
        """Evil 想伪造握手签名时只能用自己的 RSA 私钥。"""
        return self._key if self.profile.auth_kex else None

    def forward(self, d: Delivery) -> None:
        """原样转发，不改动任何字节。"""
        self.log.add(self.name, ev.FORWARD, f"原样转发 → {d.dst}")
        self.network.send(self.name, d.dst, d.data)

    def _inject(self, dst: str, msg: Message, note: str, kind: str = ev.MODIFY) -> None:
        self.log.add(self.name, kind, note, dst=dst)
        self.network.send(self.name, dst, encode(msg))

    def on_wire(self, d: Delivery) -> None:
        self.log.add(self.name, ev.INTERCEPT, f"#{d.number} {d.src}→{d.dst}：{describe(d.data)}")
        try:
            msg = decode(d.data)
        except WireError:
            self.forward(d)
            return
        handler = {
            EvilMode.PASSIVE: self._passive, EvilMode.MITM: self._mitm,
            EvilMode.IMPERSONATE: self._impersonate, EvilMode.BITFLIP: self._bitflip,
            EvilMode.REPLAY: self._replay_mode,
        }[self.mode]
        handler(d, msg)

    def _record(self, d: Delivery, msg: Message) -> None:
        if msg.type == DATA:
            self.captured.append((f"{d.src}→{d.dst}", d.data))
            self.log.add(self.name, ev.SPY, "记录到密文，但没有会话密钥，无法解密", direction=f"{d.src}→{d.dst}")

    def _passive(self, d: Delivery, msg: Message) -> None:
        self._record(d, msg)
        self.forward(d)

    def _bitflip(self, d: Delivery, msg: Message) -> None:
        if msg.type == DATA and d.src == ALICE and isinstance(msg.fields.get("ct"), bytes):
            ct = bytearray(msg.fields["ct"])
            ct[0] ^= 0x01  # 翻转首块密文的最低位：首块明文被破坏，次块明文对应位翻转
            out = msg.copy()
            out.fields["ct"] = bytes(ct)
            self._inject(d.dst, out, "翻转密文第 1 字节的最低位后转发（不需要密钥）")
        else:
            self.forward(d)

    def _replay_mode(self, d: Delivery, msg: Message) -> None:
        if msg.type == DATA and d.src == ALICE:
            self.captured.append((f"{d.src}→{d.dst}", d.data))
            self.log.add(self.name, ev.SPY, "保存该数据包，稍后重放", direction=f"{d.src}→{d.dst}")
        self.forward(d)

    def replay(self, index: int = 0) -> bool:
        """把已记录的第 index 个 Alice→Bob 数据包原样重发给 Bob。"""
        packets = [data for direction, data in self.captured if direction == f"{ALICE}→{BOB}"]
        if index >= len(packets):
            self.log.add(self.name, ev.INFO, "没有可重放的数据包")
            return False
        self.log.add(self.name, ev.REPLAY, f"重放第 {index + 1} 个记录的数据包给 Bob")
        self.network.send(self.name, BOB, packets[index])
        return True

    def has_idle_work(self) -> bool:
        """空闲时是否还有待执行的攻击动作（用于判断场景是否真正结束）。"""
        return self.mode == EvilMode.REPLAY and not self._replayed

    def on_idle(self) -> bool:
        """网络与脚本都空闲时由 World 调用；REPLAY 模式在此刻重放一次历史数据包。"""
        if self.has_idle_work():
            self._replayed = True
            return self.replay(0)
        return False

    # ---------------- DH 密钥替换 ----------------
    def _mitm(self, d: Delivery, msg: Message) -> None:
        if msg.type == KEX_INIT and d.src == ALICE:
            self._mitm_init(d, msg)
        elif msg.type == KEX_REPLY and d.src == BOB and self._hs_bob is not None:
            self._mitm_reply(d, msg)
        elif msg.type == DATA and len(self.sessions) == 2:
            self._relay_data(d, msg)
        else:
            self.forward(d)

    def _mitm_init(self, d: Delivery, msg: Message) -> None:
        y_a, nonce_a = msg.fields.get("dh_pub"), msg.fields.get("nonce")
        if not isinstance(y_a, bytes) or not isinstance(nonce_a, bytes):
            self.forward(d)
            return
        self._alice_hello = (y_a, nonce_a)
        fake_init, self._hs_bob = build_init(ALICE, BOB, self._signer())
        self._inject(BOB, fake_init, "用 Evil 自己的 DH 公钥替换 Alice 的公钥，冒充 Alice 发给 Bob")

    def _mitm_reply(self, d: Delivery, msg: Message) -> None:
        y_b, nonce_b = msg.fields.get("dh_pub"), msg.fields.get("nonce")
        y_a, nonce_a = self._alice_hello
        try:
            keys_eb = derive_keys(self._hs_bob, y_b, self._hs_bob.nonce, nonce_b)
            fake_reply, st = build_reply(BOB, ALICE, y_a, nonce_a, self._signer())
            keys_ea = derive_keys(st, y_a, nonce_a, st.nonce)
        except (HandshakeError, ValueError, TypeError):
            self.forward(d)
            return
        self.sessions[BOB] = Session(keys_eb, "A", self.profile)
        self.sessions[ALICE] = Session(keys_ea, "B", self.profile)
        self.log.add(self.name, ev.KEY,
                     f"Evil 持有两把会话密钥：与 Alice {keys_ea.fingerprint()}，与 Bob {keys_eb.fingerprint()}",
                     with_alice=keys_ea.fingerprint(), with_bob=keys_eb.fingerprint())
        self._inject(ALICE, fake_reply, "用 Evil 自己的 DH 公钥替换 Bob 的公钥，冒充 Bob 回复 Alice")

    def _relay_data(self, d: Delivery, msg: Message) -> None:
        """解密一侧的数据包，（可选）篡改，再用另一侧的密钥重新加密转发。"""
        src_session, dst_session = self.sessions[d.src], self.sessions[d.dst]
        try:
            plaintext = decode_text(src_session.open(msg.fields))
        except SessionError as exc:
            self.log.add(self.name, ev.INFO, f"无法解密该数据包：{exc}")
            self.forward(d)
            return
        self.spied.append((f"{d.src}→{d.dst}", plaintext))
        self.log.add(self.name, ev.SPY, f"窃听到明文 {d.src}→{d.dst}：{plaintext}", text=plaintext)
        new_text = plaintext
        if self.tamper is not None and d.src == ALICE:
            new_text = self.tamper(plaintext)
        if new_text != plaintext:
            self.tampered.append((plaintext, new_text))
            note = f"篡改：「{plaintext}」→「{new_text}」，用与 {d.dst} 的密钥重新加密"
        else:
            note = "用与对方的密钥重新加密后转发"
        out = Message(DATA, d.src, d.dst, dst_session.seal(new_text.encode("utf-8")))
        self._inject(d.dst, out, note)

    # ---------------- 冒充 Bob ----------------
    def _impersonate(self, d: Delivery, msg: Message) -> None:
        if msg.type == KEX_INIT and d.src == ALICE:
            y_a, nonce_a = msg.fields.get("dh_pub"), msg.fields.get("nonce")
            try:
                reply, st = build_reply(BOB, ALICE, y_a, nonce_a, self._signer())
                keys = derive_keys(st, y_a, nonce_a, st.nonce)
            except (HandshakeError, ValueError, TypeError):
                self.log.add(self.name, ev.INFO, "Alice 的握手报文无法处理，放弃冒充")
                return
            self.sessions[ALICE] = Session(keys, "B", self.profile)
            self.log.add(self.name, ev.KEY, f"Evil 以 Bob 的身份与 Alice 建立会话 {keys.fingerprint()}",
                         with_alice=keys.fingerprint())
            self._inject(ALICE, reply, "冒充 Bob 回复握手，不转发给真正的 Bob")
        elif msg.type == DATA and d.src == ALICE and ALICE in self.sessions:
            try:
                plaintext = decode_text(self.sessions[ALICE].open(msg.fields))
            except SessionError:
                return
            self.spied.append((f"{d.src}→{BOB}", plaintext))
            self.log.add(self.name, ev.SPY, f"窃听到发给 Bob 的明文：{plaintext}", text=plaintext)
            fake = Message(DATA, BOB, ALICE, self.sessions[ALICE].seal(IMPERSONATOR_REPLY.encode("utf-8")))
            self._inject(ALICE, fake, "以 Bob 的名义回复 Alice")
        else:
            self.log.add(self.name, ev.INFO, "丢弃（不转发给 Bob）")
