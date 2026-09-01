"""文本清洗模块测试。

重点验证：
1. 能删除明显噪声（导航 / 版权 / 重复行 / 控制字符）；
2. 不破坏安全知识（代码示例、Payload、CWE 编号必须保留）。
"""

from __future__ import annotations

from app.rag.cleaner import CleanConfig, TextCleaner
from app.rag.schemas import Document


class TestNoiseRemoval:
    def test_remove_nav_and_copyright_lines(self):
        text = (
            "首页\n"
            "## 漏洞描述\n"
            "SQL 注入是常见漏洞。\n"
            "版权所有 © 2025 测试站\n"
            "联系我们\n"
            "## 修复方法\n"
            "使用参数化查询。\n"
        )
        cleaned = TextCleaner().clean(text)
        assert "首页" not in cleaned
        assert "版权所有" not in cleaned
        assert "联系我们" not in cleaned
        # 知识内容保留
        assert "## 漏洞描述" in cleaned
        assert "## 修复方法" in cleaned
        assert "参数化查询" in cleaned

    def test_remove_duplicate_consecutive_lines(self):
        text = "第一行\n第一行\n第二行\n"
        cleaned = TextCleaner().clean(text)
        assert cleaned.count("第一行") == 1

    def test_remove_control_and_zero_width_chars(self):
        text = "正常文本\u200b\u200d零宽字符\x00\x01控制字符\n"
        cleaned = TextCleaner().clean(text)
        assert "\u200b" not in cleaned
        assert "\u200d" not in cleaned
        assert "\x00" not in cleaned
        assert "正常文本" in cleaned

    def test_collapse_blank_lines(self):
        text = "第一段\n\n\n\n第二段\n"
        cleaned = TextCleaner().clean(text)
        assert "\n\n\n" not in cleaned  # 最多保留一个空行


class TestPreserveSecurityKnowledge:
    def test_preserve_code_block_content(self):
        """清洗不得破坏代码块中的漏洞代码 / Payload。"""
        text = (
            "## 代码示例\n\n"
            "```java\n"
            "String sql = \"SELECT * FROM users WHERE id=\" + id;\n"
            "```\n\n"
            "首页\n"
        )
        cleaned = TextCleaner().clean(text)
        assert 'String sql = "SELECT * FROM users WHERE id=" + id;' in cleaned
        assert "```java" in cleaned

    def test_preserve_payload_in_text(self):
        """正文中的 Payload（看似 HTML 标签）不得被误删。"""
        payload = "<script>alert(1)</script>"
        text = f"## 检测载荷\n{payload}\n## 修复方法\n转义输出。\n"
        cleaned = TextCleaner().clean(text)
        assert payload in cleaned  # 默认不剥离 HTML 标签，保护 Payload

    def test_strip_html_optional(self):
        """开启 strip_html_tags 时才剥离 HTML 标签（显式选项）。"""
        text = "内容<p>段落</p>结束<script>var x=1;</script>"
        cleaned = TextCleaner(CleanConfig(strip_html_tags=True)).clean(text)
        assert "<p>" not in cleaned
        assert "<script>" not in cleaned
        assert "段落" in cleaned

    def test_preserve_cwe_ids(self):
        text = "CWE-89 SQL 注入\nCWE-79 XSS\n"
        cleaned = TextCleaner().clean(text)
        assert "CWE-89" in cleaned
        assert "CWE-79" in cleaned

    def test_preserve_heading_indentation(self):
        """行首缩进（Markdown 列表 / 引用）不被压缩。"""
        text = "## 列表\n\n- 项目一\n- 项目二\n"
        cleaned = TextCleaner().clean(text)
        assert "- 项目一" in cleaned
        assert "- 项目二" in cleaned


class TestCleanDocument:
    def test_clean_document_preserves_metadata(self):
        doc = Document(
            page_content="首页\nCWE-89 注入。\n",
            metadata={"document_name": "a.md", "cwe_id": ["CWE-89"]},
        )
        cleaned = TextCleaner().clean_document(doc)
        assert cleaned.metadata["document_name"] == "a.md"
        assert cleaned.metadata["cwe_id"] == ["CWE-89"]
        assert "CWE-89" in cleaned.page_content

    def test_empty_text(self):
        assert TextCleaner().clean("") == ""
        assert TextCleaner().clean("   \n  ") == ""
