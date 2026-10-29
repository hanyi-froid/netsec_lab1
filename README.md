# netsec_lab1 —— 中间人攻击与防御实验器

《计算机网络安全技术》课程实验一。构建 Alice、Bob、Evil 三个角色，演示正常通信、
中间人攻击（DH 密钥替换、窃听、篡改、重放）以及采用认证 DH 后的防御效果。
所有密码算法（SHA-256、HMAC、HKDF、AES-128、RSA、DH）均为自行实现，不调用任何密码库。

> 本项目在 AI 辅助下开发，开发过程记录见 `docs/` 下的实验说明文档。

## 环境

- Python 3.10+（开发环境 3.13，tkinter 随官方 Python 安装包提供）
- 运行程序：无第三方依赖
- 运行测试：`pip install -r requirements-dev.txt`（pycryptodome 仅用于测试对照）

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

## 测试

```powershell
python -m pytest -q
# 或不装 pytest：
python -m unittest discover -s tests -t .
```

## 目录结构

```
mitmlab/crypto   自行实现的密码算法
mitmlab/proto    信道、报文、角色与攻防场景
mitmlab/gui      tkinter 图形界面
tests/           单元测试与场景测试
docs/            实验说明文档
```

## 已实现算法与测试

| 模块 | 内容 | 测试依据 |
|---|---|---|
| `mitmlab/crypto/numtheory.py` | 模幂、扩展欧几里得、模逆、Miller-Rabin、素数生成 | 与内置 `pow`、试除法、pycryptodome `isPrime` 对照；Carmichael 数/强伪素数 |
| `mitmlab/crypto/sha256.py` | SHA-256（支持增量更新） | FIPS 180-4 标准向量、分组边界、`hashlib` 对照 |
| `mitmlab/crypto/hmac_hkdf.py` | HMAC-SHA256、HKDF-SHA256 | RFC 4231、RFC 5869 向量；标准库 `hmac` 与 pycryptodome 对照 |
| `mitmlab/crypto/aes.py` | AES-128/192/256、CBC、PKCS#7 | FIPS 197 附录 A/B/C、SP800-38A ECB/CBC 向量；pycryptodome 随机对照（含库加密、自实现解密） |
| `mitmlab/crypto/rsa.py` | RSA 密钥生成（CRT）、PKCS#1 v1.5 + SHA-256 DigestInfo 签名/验签 | 教科书示例；DigestInfo/EM 结构；与 pycryptodome `pkcs1_15` 签名字节一致、互相验签；伪造填充被拒 |
| `mitmlab/crypto/dh.py` | RFC 3526 1536 位 MODP 的 DH、公钥合法性校验 | 用 Machin 公式独立计算 π 校验素数公式；安全素数；与内置 `pow` 对照；0/1/p-1/非子群公钥被拒 |

## 通信协议与攻防场景（mitmlab/proto）

- 报文经 `messages.encode/decode` 序列化为 JSON bytes，`Network` 只接受 bytes，Evil 是所有流量的网关。
- 握手：DH（RFC 3526）+ 可选 RSA 签名（STS 风格，签名绑定身份、DH 公钥与双方 nonce）；会话密钥由 HKDF 派生，A→B / B→A 方向独立。
- 数据包：`seq ‖ IV ‖ AES-128-CBC ‖ HMAC-SHA256`（先加密后 MAC），接收方要求 seq 严格递增。
- 三档防御配置：无防御 / 仅 HMAC / 完整防御（签名认证 DH + HMAC + 序号）。
- 13 个预置场景（`mitmlab/proto/scenarios.py`）：正常通信、密钥替换、冒充、位翻转、重放，以及各自的防御与局限对比。

## 命令行用法

```powershell
python -m mitmlab list                 # 列出全部场景
python -m mitmlab run mitm             # 运行场景，打印各角色行为与结论
python -m mitmlab run mitm --step      # 单步：每次回车推进一步
python -m mitmlab run defended-mitm    # 同一攻击在完整防御下被阻止
python -m mitmlab all                  # 全部场景对照表
```

## 图形界面

```powershell
python -m mitmlab gui
```

- 顶部选择场景，或手动调整三个防御开关、Evil 行为、双方消息与篡改规则（自定义配置）。
- 「单步」逐步推进，「自动播放」定时推进，「一键运行」直接跑完；「Evil 立即重放」可在通信中途交互式重放数据包。
- 中间是 Alice | Evil | Bob 三泳道时序图（红色箭头为被 Evil 篡改/伪造的报文），其下是三方各自的视角与会话密钥指纹，右侧是事件日志与结果判定。
- 「对比全部场景」在后台线程运行全部场景并弹出对照表。RSA 密钥也在后台线程生成；后台任务统一通过 `queue.Queue` + `root.after()` 回到主线程刷新界面。

## 开发进度

随各阶段提交逐步更新，当前：密码算法、协议层与攻防场景完成；CLI、GUI、Bonus 与实验文档进行中。
