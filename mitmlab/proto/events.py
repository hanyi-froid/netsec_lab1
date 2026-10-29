"""事件日志：记录各角色的发送、接收、拦截、篡改、告警等行为，供 CLI/GUI 展示与测试断言。"""

from dataclasses import dataclass, field
from typing import Callable

# 事件类别
SEND = "send"            # 角色发出一条报文
RECV = "recv"            # 角色收到并处理一条报文
INFO = "info"            # 一般状态信息
KEY = "key"              # 密钥相关（协商完成、指纹）
APP = "app"              # 应用层消息送达
INTERCEPT = "intercept"  # Evil 截获
FORWARD = "forward"      # Evil 原样转发
MODIFY = "modify"        # Evil 篡改
REPLAY = "replay"        # Evil 重放
SPY = "spy"              # Evil 窃听到明文
ALERT = "alert"          # 防御机制触发告警/拒绝
NET = "net"              # 网络层投递
FAULT = "fault"          # 网络故障注入（丢包/重复/乱序）


@dataclass
class Event:
    """一条事件。actor 为产生事件的角色名，data 携带结构化细节。"""
    index: int
    actor: str
    kind: str
    text: str
    data: dict = field(default_factory=dict)


# 事件类别的中文标签，CLI 与 GUI 共用
KIND_LABELS = {
    SEND: "发送", RECV: "接收", INFO: "信息", KEY: "密钥", APP: "应用", INTERCEPT: "截获",
    FORWARD: "转发", MODIFY: "篡改", REPLAY: "重放", SPY: "窃听", ALERT: "告警",
    NET: "网络", FAULT: "故障",
}


def format_event(e: Event) -> str:
    """把事件渲染为一行文本。"""
    return f"[{e.index:03d}] {e.actor:<5} {KIND_LABELS.get(e.kind, e.kind)}  {e.text}"


class EventLog:
    """事件容器，支持订阅者回调（GUI 用它实时刷新）。"""

    def __init__(self):
        self.events: list = []
        self._subscribers: list = []

    def subscribe(self, callback: Callable[[Event], None]) -> None:
        self._subscribers.append(callback)

    def add(self, actor: str, kind: str, text: str, /, **data) -> Event:
        event = Event(len(self.events), actor, kind, text, data)
        self.events.append(event)
        for cb in self._subscribers:
            cb(event)
        return event

    def of_kind(self, *kinds: str) -> list:
        return [e for e in self.events if e.kind in kinds]
