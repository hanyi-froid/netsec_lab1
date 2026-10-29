"""安全配置：用三个独立开关描述通信双方启用了哪些防御，便于逐项对比攻防效果。"""

from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityProfile:
    """
    auth_kex    : DH 握手使用 RSA 签名认证（防密钥替换/冒充）
    mac         : 数据包带 HMAC（防篡改、位翻转）
    anti_replay : 接收方要求 seq 严格递增（防重放）；seq 被 MAC 覆盖时才可靠
    """
    name: str
    auth_kex: bool = False
    mac: bool = False
    anti_replay: bool = False

    def describe(self) -> str:
        on = [label for flag, label in
              ((self.auth_kex, "签名认证 DH"), (self.mac, "HMAC 完整性"), (self.anti_replay, "序号防重放"))
              if flag]
        return "、".join(on) if on else "无防御（明文 DH + AES-CBC）"


PLAIN = SecurityProfile("无防御")
MAC_ONLY = SecurityProfile("仅 HMAC", mac=True)
HARDENED = SecurityProfile("完整防御", auth_kex=True, mac=True, anti_replay=True)

PROFILES = {"plain": PLAIN, "mac_only": MAC_ONLY, "hardened": HARDENED}
