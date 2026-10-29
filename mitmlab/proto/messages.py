"""线路报文格式：Message 对象 <-> bytes 的严格序列化/反序列化。

信道上只允许传输 bytes。每个角色发送前调用 encode()，接收后调用 decode()，
因此 Evil 看到、修改、重放的永远是线路上的字节串，而不是对方内存里的对象。

格式为紧凑 JSON（UTF-8）：
    {"type": "...", "from": "...", "to": "...", "fields": {"name": <str|int|{"hex": "..."}>}}
bytes 字段以 {"hex": "..."} 表示。选择 JSON 是为了让界面里的报文便于阅读，
解码时做严格校验，格式错误一律抛出 WireError。
"""

import json
import unicodedata
from dataclasses import dataclass, field

KEX_INIT = "KEX_INIT"    # 握手第 1 条：发起方 DH 公钥 (+ 签名)
KEX_REPLY = "KEX_REPLY"  # 握手第 2 条：应答方 DH 公钥 (+ 签名)
DATA = "DATA"            # 应用数据：seq / iv / 密文 / mac
ALERT = "ALERT"          # 握手失败通知
MESSAGE_TYPES = {KEX_INIT, KEX_REPLY, DATA, ALERT}

MAX_WIRE_SIZE = 64 * 1024


class WireError(ValueError):
    """报文无法解析或不符合格式。"""


@dataclass
class Message:
    """协议报文。sender/receiver 只是报文里的"自称"，网络层不保证其真实性。"""
    type: str
    sender: str
    receiver: str
    fields: dict = field(default_factory=dict)

    def copy(self) -> "Message":
        return Message(self.type, self.sender, self.receiver, dict(self.fields))


def encode(msg: Message) -> bytes:
    """把 Message 序列化为线路字节串。"""
    if msg.type not in MESSAGE_TYPES:
        raise WireError(f"未知报文类型: {msg.type}")
    fields = {}
    for key, value in msg.fields.items():
        if isinstance(value, (bytes, bytearray)):
            fields[key] = {"hex": bytes(value).hex()}
        elif isinstance(value, bool) or not isinstance(value, (int, str)):
            raise WireError(f"字段 {key} 类型不受支持: {type(value).__name__}")
        else:
            fields[key] = value
    doc = {"type": msg.type, "from": msg.sender, "to": msg.receiver, "fields": fields}
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def decode(data: bytes) -> Message:
    """把线路字节串解析为 Message，任何格式问题都抛出 WireError。"""
    if not isinstance(data, (bytes, bytearray)):
        raise WireError("线路数据必须是 bytes")
    if len(data) > MAX_WIRE_SIZE:
        raise WireError("报文过大")
    try:
        doc = json.loads(bytes(data).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WireError(f"报文不是合法的 JSON: {exc}") from exc
    if not isinstance(doc, dict) or set(doc) != {"type", "from", "to", "fields"}:
        raise WireError("报文结构非法")
    if doc["type"] not in MESSAGE_TYPES:
        raise WireError(f"未知报文类型: {doc['type']!r}")
    if not isinstance(doc["from"], str) or not isinstance(doc["to"], str):
        raise WireError("from/to 必须是字符串")
    if not isinstance(doc["fields"], dict):
        raise WireError("fields 必须是对象")
    fields = {}
    for key, value in doc["fields"].items():
        if isinstance(value, dict):
            if set(value) != {"hex"} or not isinstance(value["hex"], str):
                raise WireError(f"字段 {key} 的 bytes 编码非法")
            try:
                fields[key] = bytes.fromhex(value["hex"])
            except ValueError as exc:
                raise WireError(f"字段 {key} 不是合法的十六进制") from exc
        elif isinstance(value, bool) or not isinstance(value, (int, str)):
            raise WireError(f"字段 {key} 类型不受支持")
        else:
            fields[key] = value
    return Message(doc["type"], doc["from"], doc["to"], fields)


def _short(value, limit: int = 8) -> str:
    """界面展示用的字段缩写：bytes 显示前几个字节与总长度。"""
    if isinstance(value, bytes):
        head = value[:limit].hex()
        return f"{head}…({len(value)}B)" if len(value) > limit else head or "∅"
    return str(value)


def decode_text(data: bytes) -> str:
    """显示 UTF-8 明文；损坏字节与控制字符均转义，避免替换字符或不可见字符乱码。"""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = "[非 UTF-8 数据，非法字节已转义] " + data.decode("utf-8", errors="backslashreplace")
    return "".join(
        f"\\x{ord(char):02x}" if unicodedata.category(char) == "Cc" and ord(char) <= 0xFF
        else f"\\u{ord(char):04x}" if unicodedata.category(char) == "Cc"
        else char
        for char in text
    )


def describe(data: bytes) -> str:
    """把线路字节串渲染为一行可读摘要；无法解析时标记为乱码，供日志使用。"""
    try:
        msg = decode(data)
    except WireError:
        return f"<无法解析的数据 {len(data)}B>"
    parts = [f"{k}={_short(v)}" for k, v in msg.fields.items()]
    return f"{msg.type} [{msg.sender}→{msg.receiver}] " + " ".join(parts)
