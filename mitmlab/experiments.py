"""自动化实验（Bonus）：攻防对比矩阵、网络故障注入实验，并可导出 CSV。

所有实验都基于 World 运行，结果完全由"各方可观察事实"得出，没有任何硬编码的预期值。
"""

import csv
import os
from typing import Iterable

from .proto.attacker import MODE_LABELS, EvilMode
from .proto.channel import FaultConfig
from .proto.identities import KeyRing, default_keyring
from .proto.profiles import HARDENED, MAC_ONLY, PLAIN
from .proto.scenarios import SCENARIO_BY_ID, SCENARIOS, World

ATTACK_MODES = (EvilMode.MITM, EvilMode.IMPERSONATE, EvilMode.BITFLIP, EvilMode.REPLAY)
PROFILE_LIST = (PLAIN, MAC_ONLY, HARDENED)


def defense_matrix(keyring: KeyRing = None, rsa_bits: int = 2048) -> list:
    """攻击方式 × 防御配置矩阵：每格运行一次，记录攻击是否得逞。

    返回行字典列表：attack / profile / attack_succeeded / communication_ok / alerts。
    """
    keyring = keyring or default_keyring(rsa_bits)
    rows = []
    for mode in ATTACK_MODES:
        for profile in PROFILE_LIST:
            result = World(SCENARIO_BY_ID["normal"], keyring=keyring, profile=profile, evil_mode=mode).run()
            rows.append({"attack": MODE_LABELS[mode], "profile": profile.name,
                         "attack_succeeded": result.attack_succeeded,
                         "communication_ok": result.communication_ok, "alerts": len(result.alerts)})
    return rows


def scenario_repeats(keyring: KeyRing = None, repeats: int = 5, rsa_bits: int = 2048) -> list:
    """每个预置场景重复运行多次（每次的 DH 私钥、nonce、IV 都是新随机数），统计结果是否稳定。"""
    keyring = keyring or default_keyring(rsa_bits)
    rows = []
    for s in SCENARIOS:
        results = [World(s, keyring=keyring).run() for _ in range(repeats)]
        rows.append({"scenario": s.id, "profile": s.profile.name, "runs": repeats,
                     "attack_rate": sum(r.attack_succeeded for r in results) / repeats,
                     "comm_ok_rate": sum(r.communication_ok for r in results) / repeats,
                     "expected_attack": s.attack_expected})
    return rows


FAULT_CASES = (
    ("无故障", FaultConfig()),
    ("丢包 10%", FaultConfig(drop_rate=0.1)),
    ("丢包 30%", FaultConfig(drop_rate=0.3)),
    ("重复 30%", FaultConfig(duplicate_rate=0.3)),
    ("乱序 30%", FaultConfig(reorder_rate=0.3)),
    ("丢包+重复+乱序", FaultConfig(drop_rate=0.1, duplicate_rate=0.2, reorder_rate=0.2)),
)


def fault_experiment(keyring: KeyRing = None, trials: int = 20, rsa_bits: int = 2048,
                     profiles: Iterable = (PLAIN, HARDENED)) -> list:
    """异常情况模拟：在不同网络故障下，统计握手成功率与消息完整送达率。

    故障由带种子的伪随机数产生（seed = 试验序号），整个实验可复现。
    """
    keyring = keyring or default_keyring(rsa_bits)
    rows = []
    for profile in profiles:
        for label, faults in FAULT_CASES:
            handshake_ok = comm_ok = rejected = 0
            for seed in range(trials):
                cfg = FaultConfig(faults.drop_rate, faults.duplicate_rate, faults.reorder_rate, seed)
                w = World(SCENARIO_BY_ID["normal"], keyring=keyring, profile=profile, faults=cfg)
                r = w.run()
                handshake_ok += r.alice_state == "established" and r.bob_state == "established"
                comm_ok += r.communication_ok
                rejected += bool(r.alerts)
            rows.append({"profile": profile.name, "fault": label, "trials": trials,
                         "handshake_ok_rate": handshake_ok / trials, "comm_ok_rate": comm_ok / trials,
                         "trials_with_rejections": rejected})
    return rows


def write_csv(path: str, rows: list) -> None:
    """把行字典列表写成 UTF-8（带 BOM，便于 Excel 打开）CSV。"""
    if not rows:
        raise ValueError("没有数据可写")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
