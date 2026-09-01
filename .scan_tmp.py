# -*- coding: utf-8 -*-
import re
from pathlib import Path
ROOT = Path(r"D:\毕业设计\AI驱动的Web代码安全审计多Agent系统")
files = [
    "项目阅读文档.md", "使用文档.md",
    "开发日志/2026-08-17_开发问题.md", "开发日志/2026-08-17_项目进度.markdown",
    "开发日志/2026-08-18_开发问题.md", "开发日志/2026-08-18_系统完善.md",
    "开发日志/2026-08-18_项目进度.markdown",
]
patterns = {
    "API_KEY": re.compile(r"sk-[A-Za-z0-9._-]{8,}"),
    "EMAIL": re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"),
    "WINDOWS_PATH": re.compile(r"[A-Za-z]:\\[^\"'\s]{3,}"),
    "USERNAME_PATH": re.compile(r"C:\\Users\\[^\\\s]+"),
}
for f in files:
    p = ROOT / f
    if not p.is_file():
        continue
    for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        for name, rx in patterns.items():
            for m in rx.finditer(line):
                val = m.group(0)
                if len(val) > 45:
                    val = val[:45] + "..."
                print(f"{f}:L{i} [{name}] {val}")
