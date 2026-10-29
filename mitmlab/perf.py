"""性能分析（Bonus）：自实现算法在纯 Python 下的耗时与吞吐，以及完整握手的开销对比。

说明：数值与机器有关，这里关注相对量级——例如认证 DH 比明文 DH 多出的 RSA 签名/验签开销。
"""

import time

from .crypto import aes, dh, rsa
from .crypto.hmac_hkdf import hmac_sha256
from .crypto.sha256 import sha256
from .proto.identities import KeyRing, generate_keyring
from .proto.scenarios import SCENARIO_BY_ID, World


def _best(fn, repeat: int) -> float:
    """多次运行取最短耗时（秒），减小系统抖动影响。"""
    best = float("inf")
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - start)
    return best


def run_benchmarks(quick: bool = False, keyring: KeyRing = None) -> list:
    """运行基准测试，返回 [{'item','value','unit'}, ...]。quick=True 时缩小规模与重复次数（测试用）。"""
    repeat = 1 if quick else 3
    data_size = 4 * 1024 if quick else 64 * 1024
    bits = 1024 if quick else 2048
    rows = []

    def add(item, value, unit):
        rows.append({"item": item, "value": round(value, 4), "unit": unit})

    for b in ((1024,) if quick else (1024, 2048)):
        add(f"RSA-{b} 密钥生成", _best(lambda: rsa.generate_keypair(b), 1), "s")
    keyring = keyring or generate_keyring(bits)
    key = keyring.alice
    sig = rsa.sign(key, b"benchmark")
    add(f"RSA-{bits} 签名(CRT)", _best(lambda: rsa.sign(key, b"benchmark"), repeat) * 1000, "ms")
    add(f"RSA-{bits} 验签", _best(lambda: rsa.verify(key.public, b"benchmark", sig), repeat) * 1000, "ms")

    group = dh.GROUP_1536
    add("DH-1536 生成密钥对", _best(dh.generate_keypair, repeat) * 1000, "ms")
    x, y = dh.generate_keypair()
    x2, y2 = dh.generate_keypair()
    add("DH-1536 计算共享秘密(含公钥校验)", _best(lambda: dh.shared_secret(x, y2, group), repeat) * 1000, "ms")

    payload = bytes(range(256)) * (data_size // 256)
    k, iv = bytes(16), bytes(16)
    ct = aes.cbc_encrypt(k, iv, payload)
    mb = len(payload) / 1e6
    add("AES-128-CBC 加密", mb / _best(lambda: aes.cbc_encrypt(k, iv, payload), repeat), "MB/s")
    add("AES-128-CBC 解密", mb / _best(lambda: aes.cbc_decrypt(k, iv, ct), repeat), "MB/s")
    add("SHA-256", mb / _best(lambda: sha256(payload), repeat), "MB/s")
    add("HMAC-SHA256", mb / _best(lambda: hmac_sha256(k, payload), repeat), "MB/s")

    for sid, label in (("normal", "无防御"), ("defended-normal", "完整防御")):
        t = _best(lambda: World(SCENARIO_BY_ID[sid], keyring=keyring).run(), repeat)
        add(f"完整通信流程（握手+2 条消息）：{label}", t * 1000, "ms")
    return rows
