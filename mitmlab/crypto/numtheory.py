"""数论与大整数工具：模幂、扩展欧几里得、模逆、Miller-Rabin 素性检测、素数生成。

这些是公钥密码（RSA、DH）的基础。题目允许使用大整数，但模幂/模逆/素性检测
在此均自行实现，不使用 pow(x, e, m) 与 pow(x, -1, m)（它们只在测试中用作对照）。
随机数来自标准库 secrets（操作系统 CSPRNG），属于题目允许的"随机数"基础功能。
"""

import secrets

# 小素数表：用于素性检测前的快速试除，过滤绝大多数合数
_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251,
]


def mod_exp(base: int, exp: int, mod: int) -> int:
    """快速模幂（square-and-multiply，从低位到高位）：返回 base**exp mod mod。"""
    if mod <= 0:
        raise ValueError("模数必须为正整数")
    if exp < 0:
        raise ValueError("指数必须非负；负指数请先用 mod_inv")
    if mod == 1:
        return 0
    result = 1
    base %= mod
    while exp:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


def egcd(a: int, b: int):
    """扩展欧几里得算法（迭代版）：返回 (g, x, y)，满足 a*x + b*y = g = gcd(a, b)。"""
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
    return old_r, old_x, old_y


def gcd(a: int, b: int) -> int:
    """最大公约数。"""
    return egcd(a, b)[0] if (a or b) else 0


def mod_inv(a: int, mod: int) -> int:
    """模逆元：返回满足 a*x ≡ 1 (mod mod) 的 x；a 与 mod 不互素时抛出 ValueError。"""
    if mod <= 0:
        raise ValueError("模数必须为正整数")
    g, x, _ = egcd(a % mod, mod)
    if g != 1:
        raise ValueError("a 与模数不互素，逆元不存在")
    return x % mod


def _miller_rabin_round(n: int, d: int, s: int, a: int) -> bool:
    """单轮 Miller-Rabin：以 a 为底，若 n 通过检测（可能是素数）返回 True。"""
    x = mod_exp(a, d, n)
    if x == 1 or x == n - 1:
        return True
    for _ in range(s - 1):
        x = (x * x) % n
        if x == n - 1:
            return True
    return False


def is_probable_prime(n: int, rounds: int = 40, rng=None) -> bool:
    """Miller-Rabin 素性检测。

    rounds 轮随机底数下，合数被误判的概率不超过 4**(-rounds)。
    rng 为可选的 callable(low, high)->int，便于测试时注入确定性底数。
    """
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    # 把 n-1 分解为 2**s * d（d 为奇数）
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = rng(2, n - 2) if rng else 2 + secrets.randbelow(n - 3)
        if not _miller_rabin_round(n, d, s, a):
            return False
    return True


def gen_prime(bits: int, rounds: int = 40) -> int:
    """生成指定位数的随机素数（最高两位置 1，保证两素数之积的位数；末位置 1 保证奇数）。"""
    if bits < 8:
        raise ValueError("素数位数至少为 8")
    while True:
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if is_probable_prime(cand, rounds):
            return cand


def rand_range(low: int, high: int) -> int:
    """返回 [low, high] 闭区间内的均匀随机整数。"""
    if low > high:
        raise ValueError("区间非法")
    return low + secrets.randbelow(high - low + 1)


def int_to_bytes(n: int, length: int) -> bytes:
    """大端序整数转定长字节串（即 PKCS#1 的 I2OSP）；放不下时抛 ValueError。"""
    if n < 0 or n >> (8 * length):
        raise ValueError("整数超出目标长度")
    return n.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    """大端序字节串转整数（即 PKCS#1 的 OS2IP）。"""
    return int.from_bytes(b, "big")
