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

## 开发进度

随各阶段提交逐步更新，当前：工程骨架完成。
