# -*- coding: utf-8 -*-
from pathlib import Path
ROOT = Path(r"D:\毕业设计\AI驱动的Web代码安全审计多Agent系统")

# 1) .gitignore 追加内部文档忽略
gi = ROOT / ".gitignore"
s = gi.read_text(encoding="utf-8")
block = """
# ===== 内部文档（不纳入版本管理，本地保留） =====
开发日志/
项目阅读文档.md
docs/
backend/tests/fixtures/力扣.py
"""
if "开发日志/" not in s:
    gi.write_text(s.rstrip() + "\n" + block, encoding="utf-8")
    print("ok .gitignore +内部文档忽略")

# 2) README 文档索引去掉已下线的项目阅读文档
readme = ROOT / "README.md"
s = readme.read_text(encoding="utf-8")
old = """## 文档索引

| 文档 | 说明 |
|---|---|
| [`项目阅读文档.md`](项目阅读文档.md) | 项目功能 / 架构 / 接口总览（阅读用） |
| [`使用文档.md`](使用文档.md) | 使用指南：技术栈、框架结构、接口、核心函数说明 |
"""
new = """## 文档索引

| 文档 | 说明 |
|---|---|
| [`使用文档.md`](使用文档.md) | 使用指南：技术栈、框架结构、接口、核心函数说明 |
"""
assert old in s, "README 文档索引未找到"
readme.write_text(s.replace(old, new, 1), encoding="utf-8")
print("ok README 文档索引更新")
