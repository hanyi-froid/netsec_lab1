"""AES 分组密码（FIPS 197）及 CBC 模式、PKCS#7 填充的纯 Python 实现。

支持 128/192/256 位密钥（本实验协议使用 AES-128）。
S 盒不手抄常量，而是按定义在 GF(2^8) 中求乘法逆元再做仿射变换生成，
并由单元测试对照 FIPS 197 向量验证。

状态矩阵采用 FIPS 197 的列优先布局：字节 i 位于第 i%4 行、第 i//4 列，
因此输入的 16 字节可直接作为状态使用。
"""

BLOCK_SIZE = 16


def _xtime(a: int) -> int:
    """GF(2^8) 中乘以 x（即 2），模不可约多项式 x^8+x^4+x^3+x+1 (0x11B)。"""
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def _gmul(a: int, b: int) -> int:
    """GF(2^8) 乘法（俄罗斯农民算法）。"""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


def _build_sbox():
    """按定义生成 S 盒与逆 S 盒：字节取 GF(2^8) 乘法逆元（0 映射 0），再做仿射变换。"""
    inverse = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _gmul(a, b) == 1:
                inverse[a] = b
                break
    sbox = [0] * 256
    for x in range(256):
        b = inverse[x]
        # 仿射变换：s = b ^ rotl(b,1) ^ rotl(b,2) ^ rotl(b,3) ^ rotl(b,4) ^ 0x63
        s = b
        for shift in range(1, 5):
            s ^= ((b << shift) | (b >> (8 - shift))) & 0xFF
        sbox[x] = s ^ 0x63
    inv_sbox = [0] * 256
    for x, s in enumerate(sbox):
        inv_sbox[s] = x
    return sbox, inv_sbox


SBOX, INV_SBOX = _build_sbox()

# 预计算 MixColumns / InvMixColumns 用到的常数乘法表，换取更快的运行速度
_MUL = {k: [_gmul(x, k) for x in range(256)] for k in (2, 3, 9, 11, 13, 14)}


def expand_key(key: bytes):
    """密钥扩展：返回 (轮数+1) 个 16 字节轮密钥，每个轮密钥为 int 列表。"""
    if len(key) not in (16, 24, 32):
        raise ValueError("AES 密钥长度必须为 16/24/32 字节")
    nk = len(key) // 4
    rounds = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (rounds + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]            # RotWord
            temp = [SBOX[b] for b in temp]        # SubWord
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        words.append([a ^ b for a, b in zip(words[i - nk], temp)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(rounds + 1)]


def _add_round_key(state, rk):
    return [s ^ k for s, k in zip(state, rk)]


def _sub_shift(state, box):
    """合并 SubBytes 与 ShiftRows（两者可交换）：第 r 行循环左移 r 位。"""
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = box[state[r + 4 * ((c + r) % 4)]]
    return out


def _inv_shift_sub(state, box):
    """InvShiftRows（第 r 行循环右移 r 位）与 InvSubBytes。"""
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[r + 4 * ((c + r) % 4)] = box[state[r + 4 * c]]
    return out


def _mix_columns(state):
    m2, m3 = _MUL[2], _MUL[3]
    out = [0] * 16
    for c in range(0, 16, 4):
        a0, a1, a2, a3 = state[c:c + 4]
        out[c] = m2[a0] ^ m3[a1] ^ a2 ^ a3
        out[c + 1] = a0 ^ m2[a1] ^ m3[a2] ^ a3
        out[c + 2] = a0 ^ a1 ^ m2[a2] ^ m3[a3]
        out[c + 3] = m3[a0] ^ a1 ^ a2 ^ m2[a3]
    return out


def _inv_mix_columns(state):
    m9, m11, m13, m14 = _MUL[9], _MUL[11], _MUL[13], _MUL[14]
    out = [0] * 16
    for c in range(0, 16, 4):
        a0, a1, a2, a3 = state[c:c + 4]
        out[c] = m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3]
        out[c + 1] = m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3]
        out[c + 2] = m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3]
        out[c + 3] = m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]
    return out


class AES:
    """AES 分组密码：对单个 16 字节分组加/解密。"""

    def __init__(self, key: bytes):
        self._round_keys = expand_key(bytes(key))
        self._rounds = len(self._round_keys) - 1

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("分组长度必须为 16 字节")
        rks = self._round_keys
        state = _add_round_key(list(block), rks[0])
        for r in range(1, self._rounds):
            state = _add_round_key(_mix_columns(_sub_shift(state, SBOX)), rks[r])
        state = _add_round_key(_sub_shift(state, SBOX), rks[self._rounds])
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("分组长度必须为 16 字节")
        rks = self._round_keys
        state = _add_round_key(list(block), rks[self._rounds])
        for r in range(self._rounds - 1, 0, -1):
            state = _inv_shift_sub(state, INV_SBOX)
            state = _inv_mix_columns(_add_round_key(state, rks[r]))
        state = _add_round_key(_inv_shift_sub(state, INV_SBOX), rks[0])
        return bytes(state)


def pkcs7_pad(data: bytes, block: int = BLOCK_SIZE) -> bytes:
    """PKCS#7 填充：补 n 个值为 n 的字节（n 为 1..block，数据恰好对齐时补满一块）。"""
    n = block - len(data) % block
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block: int = BLOCK_SIZE) -> bytes:
    """去除并校验 PKCS#7 填充，格式非法时抛 ValueError。"""
    if not data or len(data) % block:
        raise ValueError("填充数据长度非法")
    n = data[-1]
    if n < 1 or n > block or data[-n:] != bytes([n]) * n:
        raise ValueError("PKCS#7 填充非法")
    return data[:-n]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """ECB 模式（无填充，data 须为 16 的倍数）。仅用于测试对照，协议中不使用。"""
    if len(data) % BLOCK_SIZE:
        raise ValueError("ECB 输入长度须为 16 的倍数")
    cipher = AES(key)
    return b"".join(cipher.encrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))


def ecb_decrypt(key: bytes, data: bytes) -> bytes:
    if len(data) % BLOCK_SIZE:
        raise ValueError("ECB 输入长度须为 16 的倍数")
    cipher = AES(key)
    return b"".join(cipher.decrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))


def cbc_encrypt_raw(key: bytes, iv: bytes, data: bytes) -> bytes:
    """CBC 加密（无填充，data 须为 16 的倍数）：C_i = E(P_i xor C_{i-1})，C_0 = IV。"""
    if len(iv) != BLOCK_SIZE or len(data) % BLOCK_SIZE:
        raise ValueError("IV 须为 16 字节，数据长度须为 16 的倍数")
    cipher = AES(key)
    prev, out = iv, []
    for i in range(0, len(data), 16):
        prev = cipher.encrypt_block(_xor(data[i:i + 16], prev))
        out.append(prev)
    return b"".join(out)


def cbc_decrypt_raw(key: bytes, iv: bytes, data: bytes) -> bytes:
    """CBC 解密（无填充）：P_i = D(C_i) xor C_{i-1}。"""
    if len(iv) != BLOCK_SIZE or len(data) % BLOCK_SIZE:
        raise ValueError("IV 须为 16 字节，数据长度须为 16 的倍数")
    cipher = AES(key)
    prev, out = iv, []
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        out.append(_xor(cipher.decrypt_block(block), prev))
        prev = block
    return b"".join(out)


def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES-CBC + PKCS#7 填充加密，返回密文（不含 IV）。"""
    return cbc_encrypt_raw(key, iv, pkcs7_pad(plaintext))


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-CBC + PKCS#7 去填充解密。"""
    return pkcs7_unpad(cbc_decrypt_raw(key, iv, ciphertext))
