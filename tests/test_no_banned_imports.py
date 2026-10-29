"""源码合规自检：核心包 mitmlab 不得引用任何现成密码库。

通过 AST 解析 mitmlab 下全部 .py 文件，检查：
  1. import / from ... import 语句；
  2. __import__("x")、importlib.import_module("x") 形式的动态导入。
测试代码（tests/）允许使用这些库做对照，不在扫描范围内。
"""

import ast
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGE_DIR = ROOT / "mitmlab"

# 被禁止的顶层模块名（小写比较，避免 Crypto/crypto 大小写绕过）
BANNED = {
    "hashlib", "hmac", "ssl",
    "crypto", "cryptodome", "cryptography", "pycrypto", "pycryptodome",
    "openssl", "nacl", "rsa", "ecdsa", "paramiko", "bcrypt", "passlib",
}
# 注意：本包自己的 crypto 子包通过相对导入或 mitmlab.crypto 引用，顶层名不在禁用列表内，属于合法


def _violations(source: str, filename: str):
    """返回源码中所有违规引用的 (文件, 行号, 模块名) 列表。"""
    tree = ast.parse(source, filename=filename)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0].lower()
                if top in BANNED:
                    found.append((filename, node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:  # level>0 是包内相对导入，放行
                top = node.module.split(".")[0].lower()
                if top in BANNED:
                    found.append((filename, node.lineno, node.module))
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else (
                func.attr if isinstance(func, ast.Attribute) else None)
            if name in ("__import__", "import_module") and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    top = arg.value.split(".")[0].lower()
                    if top in BANNED:
                        found.append((filename, node.lineno, arg.value))
                else:
                    # 非字面量的动态导入无法静态判定，一律视为违规
                    found.append((filename, node.lineno, "<dynamic import>"))
    return found


class BannedImportScanTest(unittest.TestCase):
    def test_package_exists(self):
        self.assertTrue(PACKAGE_DIR.is_dir())

    def test_core_package_has_no_banned_imports(self):
        files = sorted(PACKAGE_DIR.rglob("*.py"))
        self.assertTrue(files, "未找到任何源文件")
        violations = []
        for path in files:
            violations += _violations(path.read_text(encoding="utf-8"), str(path))
        self.assertEqual(violations, [], f"发现被禁密码库引用: {violations}")

    # 以下用例验证扫描器本身能识别各种违规写法，防止检测形同虚设
    def test_scanner_detects_plain_import(self):
        self.assertTrue(_violations("import hashlib", "x.py"))
        self.assertTrue(_violations("import Crypto.Cipher.AES", "x.py"))

    def test_scanner_detects_from_import(self):
        self.assertTrue(_violations("from cryptography.hazmat import x", "x.py"))
        self.assertTrue(_violations("from hmac import new", "x.py"))

    def test_scanner_detects_dynamic_import(self):
        self.assertTrue(_violations("__import__('hashlib')", "x.py"))
        self.assertTrue(_violations("importlib.import_module('ssl')", "x.py"))
        self.assertTrue(_violations("__import__(name)", "x.py"))

    def test_scanner_allows_legit_imports(self):
        src = "import os\nimport secrets\nfrom . import sha256\nfrom mitmlab.crypto import aes"
        self.assertEqual(_violations(src, "x.py"), [])


if __name__ == "__main__":
    unittest.main()
