"""攻防场景定义、世界构建（World）与结果分析。

World 把 Alice、Bob、Evil、网络和事件日志装配在一起，并按"脚本"驱动通信：
每次 step() 要么投递网络中的一条报文，要么执行脚本的下一步，因此既能一键跑完，
也能单步演示。结果分析只看各方的"可观察事实"（谁收到了什么、Evil 读到了什么），
据此判断攻击是否成功、防御是否生效。
"""

from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from . import events as ev
from .attacker import Evil, EvilMode
from .channel import FaultConfig, Network
from .identities import KeyRing, default_keyring
from .profiles import HARDENED, MAC_ONLY, PLAIN, SecurityProfile
from .roles import ESTABLISHED, Party

ALICE_TEXT = "转账 100 元给 Bob，请确认"
BOB_TEXT = "已收到转账 100 元，谢谢"
DEFAULT_SCRIPT = (("Alice", "handshake", ""), ("Alice", "say", ALICE_TEXT), ("Bob", "say", BOB_TEXT))


def default_tamper(text: str) -> str:
    """默认篡改规则：把金额 100 改成 10000。"""
    return text.replace("100", "10000")


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    category: str            # normal / attack / defense
    description: str
    profile: SecurityProfile
    evil_mode: EvilMode
    attack_expected: bool    # 预期攻击是否得逞
    comm_expected: bool      # 预期双方能否完成无异常的正常通信
    script: tuple = DEFAULT_SCRIPT


SCENARIOS = [
    Scenario("normal", "正常通信（Evil 仅转发）", "normal",
             "无防御配置下，Alice 与 Bob 通过 DH 协商密钥后加密通信；Evil 只转发，只能看到密文。",
             PLAIN, EvilMode.PASSIVE, False, True),
    Scenario("mitm", "攻击：DH 密钥替换（窃听 + 篡改）", "attack",
             "Evil 截获双方 DH 公钥并替换成自己的，分别与两人建立会话，读取并篡改明文。",
             PLAIN, EvilMode.MITM, True, False),
    Scenario("impersonate", "攻击：冒充 Bob", "attack",
             "Evil 截获 Alice 的握手后自己扮演 Bob，Alice 无从分辨。",
             PLAIN, EvilMode.IMPERSONATE, True, False),
    Scenario("bitflip", "攻击：密文位翻转（无 MAC）", "attack",
             "CBC 本身不保证完整性，Evil 不需要密钥即可翻转密文位，使 Bob 收到被改动的内容。",
             PLAIN, EvilMode.BITFLIP, True, False),
    Scenario("replay", "攻击：重放数据包（无防重放）", "attack",
             "Evil 记录 Alice 的转账指令并稍后原样重发，Bob 会再次接受。",
             PLAIN, EvilMode.REPLAY, True, False),
    Scenario("mac-vs-bitflip", "防御：HMAC 抵御位翻转", "defense",
             "启用 HMAC 后，被翻转的数据包 MAC 校验失败，被 Bob 丢弃。",
             MAC_ONLY, EvilMode.BITFLIP, False, False),
    Scenario("mac-vs-mitm", "局限：只有 HMAC 挡不住密钥替换", "attack",
             "HMAC 的密钥来自未认证的 DH，Evil 同样拥有双方的会话密钥，完整性保护形同虚设。",
             MAC_ONLY, EvilMode.MITM, True, False),
    Scenario("mac-vs-replay", "局限：只有 HMAC 挡不住重放", "attack",
             "重放的是一个 MAC 完全合法的旧数据包，没有序号检查时仍会被接受。",
             MAC_ONLY, EvilMode.REPLAY, True, False),
    Scenario("defended-normal", "防御后：正常通信", "defense",
             "启用签名认证 DH + HMAC + 序号后，Alice 与 Bob 仍能正常通信。",
             HARDENED, EvilMode.PASSIVE, False, True),
    Scenario("defended-mitm", "防御：签名认证 DH 阻止密钥替换", "defense",
             "Evil 替换 DH 公钥，但无法伪造 Alice/Bob 的 RSA 签名，握手被中止。",
             HARDENED, EvilMode.MITM, False, False),
    Scenario("defended-impersonate", "防御：签名认证阻止冒充", "defense",
             "Evil 用自己的密钥签名冒充 Bob，Alice 用预置的 Bob 公钥验签失败。",
             HARDENED, EvilMode.IMPERSONATE, False, False),
    Scenario("defended-bitflip", "防御：完整防御抵御位翻转", "defense",
             "MAC 校验失败，被篡改的数据包被丢弃。",
             HARDENED, EvilMode.BITFLIP, False, False),
    Scenario("defended-replay", "防御：序号 + MAC 抵御重放", "defense",
             "重放的数据包序号不大于已接收的最大序号，被拒绝。",
             HARDENED, EvilMode.REPLAY, False, True),
]
SCENARIO_BY_ID = {s.id: s for s in SCENARIOS}


@dataclass
class ScenarioResult:
    """一次运行的客观结果。"""
    scenario_id: str
    alice_state: str
    bob_state: str
    alice_sent: list
    alice_received: list
    bob_sent: list
    bob_received: list
    evil_spied: list
    evil_tampered: list
    alerts: list
    fingerprints: dict
    eavesdropped: bool = False
    forged_delivered: list = field(default_factory=list)
    duplicates_accepted: int = 0
    attack_succeeded: bool = False
    defense_triggered: bool = False
    communication_ok: bool = False
    summary: str = ""


class World:
    def __init__(self, scenario: Scenario, keyring: KeyRing = None, rsa_bits: int = 2048,
                 faults: FaultConfig = None, script: Optional[tuple] = None, profile=None,
                 evil_mode: Optional[EvilMode] = None):
        self.scenario = scenario
        self.profile = profile or scenario.profile
        keyring = keyring or default_keyring(rsa_bits)
        self.log = ev.EventLog()
        self.network = Network(self.log, gateway="Evil", faults=faults)
        self.alice = Party("Alice", "Bob", self.network, self.log, keyring.alice,
                           keyring.trust_for("Alice"), self.profile, is_initiator=True)
        self.bob = Party("Bob", "Alice", self.network, self.log, keyring.bob,
                         keyring.trust_for("Bob"), self.profile, is_initiator=False)
        mode = evil_mode or scenario.evil_mode
        self.evil = Evil(self.network, self.log, self.profile, keyring.evil, mode=mode,
                         tamper=default_tamper if mode == EvilMode.MITM else None)
        self._script = deque(script if script is not None else scenario.script)
        self.steps = 0

    @property
    def finished(self) -> bool:
        return not self.network.pending() and not self._script and not self.evil.has_idle_work()

    def step(self) -> Optional[str]:
        """推进一步并返回描述；全部结束返回 None。"""
        if self.network.pending():
            d = self.network.step()
            self.steps += 1
            return f"网络投递 #{d.number}：{d.src}→{d.hop}"
        if self._script:
            who, action, arg = self._script.popleft()
            party = self.alice if who == "Alice" else self.bob
            self.steps += 1
            if action == "handshake":
                party.start_handshake()
                return f"{who} 发起握手"
            party.send_text(arg)
            return f"{who} 发送消息"
        if self.evil.on_idle():
            self.steps += 1
            return "Evil 重放历史数据包"
        return None

    def run(self, max_steps: int = 10000) -> ScenarioResult:
        """一次跑完全部步骤并分析结果。"""
        while self.step() is not None:
            if self.steps > max_steps:
                raise RuntimeError("场景步数超限")
        return self.analyze()

    def analyze(self) -> ScenarioResult:
        a, b, e = self.alice, self.bob, self.evil
        fps = {"Alice": a.key_fingerprint, "Bob": b.key_fingerprint, **{f"Evil↔{k}": v for k, v in e.key_fingerprints.items()}}
        res = ScenarioResult(self.scenario.id, a.state, b.state, list(a.sent), list(a.received),
                             list(b.sent), list(b.received), list(e.spied), list(e.tampered),
                             a.alerts + b.alerts, fps)
        res.eavesdropped = bool(e.spied)
        # 送达的内容并非对方真实发出过的，视为被伪造/篡改
        res.forged_delivered = [t for t in b.received if t not in a.sent] + \
                               [t for t in a.received if t not in b.sent]
        res.duplicates_accepted = (len(b.received) - len(set(b.received))) + \
                                  (len(a.received) - len(set(a.received)))
        res.attack_succeeded = (res.eavesdropped or bool(res.forged_delivered)
                                or res.duplicates_accepted > 0)
        res.defense_triggered = bool(res.alerts)
        res.communication_ok = (a.state == ESTABLISHED and b.state == ESTABLISHED
                                and b.received == a.sent and a.received == b.sent)
        res.summary = self._summarize(res)
        return res

    def _summarize(self, r: ScenarioResult) -> str:
        lines = []
        if r.eavesdropped:
            lines.append(f"Evil 读到了 {len(r.evil_spied)} 条明文：" + "；".join(t for _, t in r.evil_spied))
        if r.evil_tampered:
            o, n = r.evil_tampered[0]
            lines.append(f"Evil 篡改了消息：「{o}」→「{n}」")
        if r.forged_delivered:
            lines.append("收到了对方从未发送的内容：" + "；".join(r.forged_delivered))
        if r.duplicates_accepted:
            lines.append(f"重复接受了 {r.duplicates_accepted} 条重放消息")
        if r.defense_triggered:
            lines.append(f"防御机制触发 {len(r.alerts)} 次告警：" + " | ".join(r.alerts))
        lines.append("攻击成功 ✗" if r.attack_succeeded else "攻击未得逞 ✓")
        lines.append("双方正常通信完成" if r.communication_ok else "通信未完整完成")
        return "\n".join(lines)


def run_scenario(scenario_id: str, **kwargs) -> ScenarioResult:
    """按 id 运行一个预置场景并返回结果。"""
    return World(SCENARIO_BY_ID[scenario_id], **kwargs).run()
