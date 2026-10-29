"""模拟网络信道。

Network 只搬运 bytes：send() 拒绝任何非 bytes 对象，接收方必须自己 decode。
拓扑：Alice 与 Bob 之间的所有流量都先经过网关节点（默认 Evil），再由网关决定转发、
修改还是丢弃——这就是"Evil 能够参与消息转发"。网关发出的流量则直接送达目的地。

投递是离散事件：send() 只入队，step() 每次投递一条，既方便单步演示，也便于注入故障
（丢包、重复、乱序），整个过程是确定性的（故障使用带种子的伪随机数）。
"""

import random
from collections import deque
from dataclasses import dataclass

from . import events as ev
from .messages import describe


@dataclass(frozen=True)
class Delivery:
    """一次逐跳投递。src 是本跳发送者，hop 是本跳接收者，dst 是报文最终目的地。"""
    number: int
    src: str
    hop: str
    dst: str
    data: bytes


@dataclass
class FaultConfig:
    """网络故障注入配置，概率取值 0~1。"""
    drop_rate: float = 0.0
    duplicate_rate: float = 0.0
    reorder_rate: float = 0.0
    seed: int = 0


class Network:
    def __init__(self, log: ev.EventLog, gateway: str = "Evil", faults: FaultConfig = None):
        self.log = log
        self.gateway = gateway
        self.faults = faults or FaultConfig()
        self._rng = random.Random(self.faults.seed)
        self._nodes: dict = {}
        self._queue: deque = deque()
        self._counter = 0
        self.delivered: list = []  # 已投递的全部记录（含 bytes），供测试检查线路内容

    def register(self, node) -> None:
        """注册节点；节点需有 name 属性与 on_wire(delivery) 方法。"""
        self._nodes[node.name] = node

    def send(self, src: str, dst: str, data: bytes) -> None:
        """从 src 发往 dst。只接受 bytes；若存在网关且发送者不是网关，则先送到网关。"""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("信道只允许传输 bytes，请先序列化")
        if dst not in self._nodes:
            raise KeyError(f"未知目的地: {dst}")
        data = bytes(data)  # 拷贝为不可变字节串，发送方此后修改原缓冲区不影响线路上的数据
        hop = self.gateway if (self.gateway in self._nodes and src != self.gateway) else dst
        self._enqueue(src, hop, dst, data)

    def _enqueue(self, src: str, hop: str, dst: str, data: bytes) -> None:
        f = self.faults
        if f.drop_rate and self._rng.random() < f.drop_rate:
            self.log.add("网络", ev.FAULT, f"丢包: {src}→{hop} {describe(data)}", src=src, hop=hop)
            return
        copies = 2 if (f.duplicate_rate and self._rng.random() < f.duplicate_rate) else 1
        if copies == 2:
            self.log.add("网络", ev.FAULT, f"重复投递: {src}→{hop}", src=src, hop=hop)
        for _ in range(copies):
            self._counter += 1
            item = Delivery(self._counter, src, hop, dst, data)
            if f.reorder_rate and self._queue and self._rng.random() < f.reorder_rate:
                self._queue.appendleft(item)  # 插队到最前，模拟乱序
                self.log.add("网络", ev.FAULT, f"乱序: #{item.number} 插队", src=src, hop=hop)
            else:
                self._queue.append(item)

    def pending(self) -> int:
        return len(self._queue)

    def step(self):
        """投递队首的一条消息；队列为空返回 None。"""
        if not self._queue:
            return None
        d = self._queue.popleft()
        self.delivered.append(d)
        self.log.add("网络", ev.NET, f"#{d.number} {d.src}→{d.hop}  {describe(d.data)}",
                     src=d.src, hop=d.hop, dst=d.dst, size=len(d.data), delivery=d.number)
        self._nodes[d.hop].on_wire(d)
        return d

    def run_until_idle(self, max_steps: int = 10000) -> int:
        """持续投递直到队列为空，返回投递条数；超过 max_steps 视为异常循环。"""
        count = 0
        while self._queue:
            if count >= max_steps:
                raise RuntimeError("网络投递步数超限，疑似消息循环")
            self.step()
            count += 1
        return count
