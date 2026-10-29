"""通信双方 Alice / Bob 的角色实现。

Party 负责：握手（发起/应答）、建立会话、收发加密消息，并在安全配置允许的范围内
拒绝可疑报文（签名错误、MAC 错误、重放等），所有行为都写入事件日志。
所有报文都经 messages.encode/decode 与 Network 交互，角色之间不共享任何内存对象。
"""

from . import events as ev
from .channel import Delivery, Network
from .handshake import (HandshakeError, build_init, build_reply, derive_keys,
                        process_init, process_reply)
from .messages import ALERT, DATA, KEX_INIT, KEX_REPLY, Message, WireError, decode, describe, encode
from .profiles import SecurityProfile
from .session import Session, SessionError

IDLE, AWAIT_REPLY, ESTABLISHED, ABORTED = "idle", "await_reply", "established", "aborted"


class Endpoint:
    """所有角色的基类：持有名称、网络与日志，提供发送报文的统一入口。"""

    def __init__(self, name: str, network: Network, log: ev.EventLog):
        self.name, self.network, self.log = name, network, log
        network.register(self)

    def emit(self, dst: str, msg: Message) -> None:
        """序列化并发送：这是角色把报文放上线路的唯一途径。"""
        data = encode(msg)
        self.log.add(self.name, ev.SEND, describe(data), message=msg.type, dst=dst)
        self.network.send(self.name, dst, data)

    def on_wire(self, delivery: Delivery) -> None:  # pragma: no cover - 由子类实现
        raise NotImplementedError


class Party(Endpoint):
    """通信一方。is_initiator=True 的角色（Alice）主动发起握手。"""

    def __init__(self, name: str, peer: str, network: Network, log: ev.EventLog, signing_key,
                 trust: dict, profile: SecurityProfile, is_initiator: bool):
        super().__init__(name, network, log)
        self.peer, self.profile, self.is_initiator = peer, profile, is_initiator
        self._signing_key = signing_key
        self._trusted_peer_key = trust.get(peer)
        self.state = IDLE
        self.session = None
        self._hs = None
        self.sent: list = []       # 本方发出的明文
        self.received: list = []   # 本方成功接收的明文
        self.alerts: list = []     # 防御机制给出的告警文本

    @property
    def key_fingerprint(self):
        return self.session.keys.fingerprint() if self.session else None

    def _auth_key(self):
        """启用签名认证时返回验签用的对端公钥；对端公钥缺失视为配置错误。"""
        if not self.profile.auth_kex:
            return None
        if self._trusted_peer_key is None:
            raise RuntimeError(f"{self.name} 未预置 {self.peer} 的公钥")
        return self._trusted_peer_key

    def _alert(self, text: str, notify_peer: bool = False) -> None:
        self.alerts.append(text)
        self.log.add(self.name, ev.ALERT, text)
        if notify_peer:
            self.emit(self.peer, Message(ALERT, self.name, self.peer, {"reason": text}))

    def _abort(self, reason: str) -> None:
        self.state = ABORTED
        self._alert(f"握手中止：{reason}", notify_peer=True)

    def start_handshake(self) -> None:
        """发起方发送 KEX_INIT（启用 auth_kex 时附带签名）。"""
        if not self.is_initiator or self.state != IDLE:
            self.log.add(self.name, ev.INFO, "当前状态不能发起握手")
            return
        msg, self._hs = build_init(self.name, self.peer,
                                   self._signing_key if self.profile.auth_kex else None)
        self.state = AWAIT_REPLY
        self.emit(self.peer, msg)

    def send_text(self, text: str) -> bool:
        """加密并发送一条文本；会话未建立时返回 False。"""
        if self.state != ESTABLISHED:
            self.log.add(self.name, ev.INFO, f"会话未建立（状态 {self.state}），无法发送：{text}")
            return False
        fields = self.session.seal(text.encode("utf-8"))
        self.sent.append(text)
        self.log.add(self.name, ev.APP, f"明文发出：{text}", text=text)
        self.emit(self.peer, Message(DATA, self.name, self.peer, fields))
        return True

    def on_wire(self, delivery: Delivery) -> None:
        try:
            msg = decode(delivery.data)
        except WireError as exc:
            self._alert(f"收到无法解析的报文，已丢弃（{exc}）")
            return
        self.log.add(self.name, ev.RECV, describe(delivery.data))
        if msg.type == KEX_INIT:
            self._on_kex_init(msg)
        elif msg.type == KEX_REPLY:
            self._on_kex_reply(msg)
        elif msg.type == DATA:
            self._on_data(msg)
        elif msg.type == ALERT and self.state == AWAIT_REPLY:
            self.state = ABORTED
            self._alert(f"对方通知握手失败：{msg.fields.get('reason', '')}")

    def _establish(self, keys, role: str) -> None:
        self.session = Session(keys, role, self.profile)
        self.state = ESTABLISHED
        self.log.add(self.name, ev.KEY, f"会话建立，密钥指纹 {keys.fingerprint()}",
                     fingerprint=keys.fingerprint())

    def _on_kex_init(self, msg: Message) -> None:
        if self.is_initiator or self.state != IDLE:
            self._alert("忽略意外的握手请求（本方已发起握手或已有会话）")
            return
        try:
            y_a, nonce_a = process_init(msg, self.name, self.peer, self._auth_key())
            reply, st = build_reply(self.name, self.peer, y_a, nonce_a,
                                    self._signing_key if self.profile.auth_kex else None)
            keys = derive_keys(st, y_a, nonce_a, st.nonce)
        except HandshakeError as exc:
            self._abort(str(exc))
            return
        self._hs = st
        self.emit(self.peer, reply)
        self._establish(keys, "B")

    def _on_kex_reply(self, msg: Message) -> None:
        if self.state != AWAIT_REPLY:
            self._alert("忽略意外的握手应答")
            return
        try:
            y_b, nonce_b = process_reply(msg, self.name, self.peer, self._hs, self._auth_key())
            keys = derive_keys(self._hs, y_b, self._hs.nonce, nonce_b)
        except HandshakeError as exc:
            self._abort(str(exc))
            return
        self._establish(keys, "A")

    def _on_data(self, msg: Message) -> None:
        if self.state != ESTABLISHED:
            self._alert("会话未建立，丢弃数据包")
            return
        try:
            plaintext = self.session.open(msg.fields)
        except SessionError as exc:
            self._alert(f"数据包被拒绝：{type(exc).__name__}（{exc}）")
            return
        text = plaintext.decode("utf-8", errors="replace")
        self.received.append(text)
        self.log.add(self.name, ev.APP, f"解密得到：{text}", text=text)
