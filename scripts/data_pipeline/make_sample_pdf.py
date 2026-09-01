"""生成测试用 PDF 样例（SQL 注入速查卡）。

用途：为 data/raw 知识库提供 PDF 格式样例，验证 PDF 加载器；
也可被测试复用（tests 中调用本模块生成 fixture）。

用法：
    python scripts/data_pipeline/make_sample_pdf.py [--output path]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # noqa: E402
from reportlab.lib.units import mm  # noqa: E402
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer  # noqa: E402

DEFAULT_OUTPUT = (
    Path(__file__).resolve().parents[2]
    / "backend" / "data" / "raw" / "quick_reference"
    / "sql_injection_cheatsheet.pdf"
)

CONTENT = [
    ("H1", "SQL 注入速查卡（SQL Injection Cheatsheet）"),
    ("Body", "本文档为 PDF 格式样例，用于验证 PDF 加载器，内容为原创整理。"),
    ("H2", "1. 常见载荷"),
    ("Code", "$id = 1 OR 1=1\n' OR '1'='1\n1 UNION SELECT username,password FROM users"),
    ("H2", "2. 检测要点"),
    ("Body", "搜索 SQL 字符串拼接模式；注入单引号与布尔载荷观察响应差异。"),
    ("H2", "3. 修复方法"),
    ("Body", "使用参数化查询（PreparedStatement / 占位符 ?），禁止拼接 SQL。"),
    ("Code", "PreparedStatement ps = conn.prepareStatement(\n    \"SELECT * FROM users WHERE id=?\");\nps.setString(1, userId);"),
    ("H2", "4. 关联编号"),
    ("Body", "CWE-89，OWASP A03:2021 Injection。"),
]


def build_pdf(output: Path) -> Path:
    """生成样例 PDF，返回输出路径。"""
    output.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    code_style = ParagraphStyle(
        "CodeBlock",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        leftIndent=6 * mm,
        backColor="#f2f2f2",
    )

    doc = SimpleDocTemplate(
        str(output), pagesize=A4,
        topMargin=20 * mm, bottomMargin=20 * mm,
    )
    flow: list = []
    for kind, text in CONTENT:
        if kind == "H1":
            flow.append(Paragraph(text, styles["Title"]))
        elif kind == "H2":
            flow.append(Spacer(1, 4 * mm))
            flow.append(Paragraph(text, styles["Heading2"]))
        elif kind == "Code":
            flow.append(Spacer(1, 2 * mm))
            flow.append(Paragraph(text.replace("\n", "<br/>"), code_style))
        else:
            flow.append(Paragraph(text, styles["BodyText"]))
    doc.build(flow)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="生成 SQL 注入速查卡样例 PDF")
    parser.add_argument("--output", type=str, default=None, help="输出路径")
    args = parser.parse_args()
    output = Path(args.output) if args.output else DEFAULT_OUTPUT
    result = build_pdf(output)
    print(f"PDF 生成完成: {result} ({result.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
