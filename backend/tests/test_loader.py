"""文档加载模块测试。"""

from __future__ import annotations

import pytest

from app.rag.loader import (
    DocumentLoadError,
    DocumentLoaderRegistry,
    load_documents,
    load_documents_from_dir,
)


class TestRegistry:
    def test_supported_formats_registered(self):
        """Markdown / TXT / JSON / HTML / PDF 均已注册。"""
        registered = DocumentLoaderRegistry.registered_extensions()
        for ext in (".md", ".markdown", ".txt", ".json", ".html", ".htm", ".pdf"):
            assert ext in registered, f"{ext} 未注册"

    def test_get_loader_by_extension(self):
        """按扩展名正确分发 Loader。"""
        from app.rag.loader.html_loader import HtmlLoader
        from app.rag.loader.json_loader import JsonLoader
        from app.rag.loader.markdown_loader import MarkdownLoader
        from app.rag.loader.pdf_loader import PdfLoader
        from app.rag.loader.text_loader import TextLoader

        assert DocumentLoaderRegistry.get_loader_cls("a.md") is MarkdownLoader
        assert DocumentLoaderRegistry.get_loader_cls("a.txt") is TextLoader
        assert DocumentLoaderRegistry.get_loader_cls("a.json") is JsonLoader
        assert DocumentLoaderRegistry.get_loader_cls("a.html") is HtmlLoader
        assert DocumentLoaderRegistry.get_loader_cls("a.pdf") is PdfLoader

    def test_unknown_extension_raises(self):
        """未注册格式抛出 DocumentLoadError。"""
        with pytest.raises(DocumentLoadError):
            load_documents("not_exist.docx")

    def test_missing_file_raises(self):
        with pytest.raises(DocumentLoadError):
            load_documents("no_such_file.md")


class TestMarkdownLoader:
    def test_load_markdown(self, fixtures_dir):
        docs = load_documents(fixtures_dir / "sample.md")
        assert len(docs) == 1
        doc = docs[0]
        assert "SQL 注入" in doc.page_content
        # 基础 metadata
        assert doc.metadata["document_name"] == "sample.md"
        assert doc.metadata["file_type"] == "md"
        assert doc.metadata["category"] == "fixtures"
        assert doc.metadata["source"].endswith("sample.md")
        # 标题提取
        assert doc.metadata["title"] == "测试用 Markdown 样例：SQL 注入"
        # 文档级 CWE 提取
        assert "CWE-89" in doc.metadata["cwe_id"]


class TestTextLoader:
    def test_load_txt(self, fixtures_dir):
        docs = load_documents(fixtures_dir / "sample.txt")
        assert len(docs) == 1
        assert "参数化查询" in docs[0].page_content
        assert docs[0].metadata["file_type"] == "txt"


class TestJsonLoader:
    def test_load_json_extracts_metadata(self, fixtures_dir):
        docs = load_documents(fixtures_dir / "sample.json")
        assert len(docs) == 1
        doc = docs[0]
        # 白名单键提升为 metadata
        assert doc.metadata["cwe_id"] == "CWE-79"
        assert doc.metadata["vulnerability_type"] == "Injection"
        assert doc.metadata["severity"] == "High"
        # 非白名单键进入正文
        assert "XSS 漏洞测试数据" in doc.page_content
        assert "JavaScript" in doc.page_content

    def test_load_json_array(self, tmp_path):
        """JSON 数组每个元素一个 Document，并带 item_index。"""
        import json

        path = tmp_path / "list.json"
        path.write_text(
            json.dumps(
                [{"cwe_id": "CWE-89", "name": "SQLi"}, {"cwe_id": "CWE-79", "name": "XSS"}]
            ),
            encoding="utf-8",
        )
        docs = load_documents(path)
        assert len(docs) == 2
        assert docs[0].metadata["item_index"] == 0
        assert docs[1].metadata["item_index"] == 1
        assert docs[0].metadata["cwe_id"] == "CWE-89"


class TestHtmlLoader:
    def test_load_html_strips_nav(self, fixtures_dir):
        docs = load_documents(fixtures_dir / "sample.html")
        assert len(docs) == 1
        content = docs[0].page_content
        # 导航与页脚噪声在加载阶段已剔除
        assert "首页" not in content
        assert "关于我们" not in content
        assert "版权所有" not in content
        # 正文保留
        assert "XSS（CWE-79）" in content
        assert "修复方法" in content
        # title 提取
        assert docs[0].metadata["title"] == "测试 HTML 文档"


class TestPdfLoader:
    def test_load_pdf(self, sample_pdf):
        docs = load_documents(sample_pdf)
        assert len(docs) == 1
        content = docs[0].page_content
        assert "SQL" in content
        assert "CWE-89" in content
        assert docs[0].metadata["page_count"] >= 1
        assert docs[0].metadata["file_type"] == "pdf"


class TestLoadFromDir:
    def test_load_all_formats(self, fixtures_dir):
        docs = load_documents_from_dir(fixtures_dir)
        names = {d.metadata["document_name"] for d in docs}
        assert "sample.md" in names
        assert "sample.txt" in names
        assert "sample.json" in names
        assert "sample.html" in names

    def test_filter_extensions(self, fixtures_dir):
        docs = load_documents_from_dir(fixtures_dir, extensions=[".md"])
        assert all(d.metadata["file_type"] == "md" for d in docs)
        assert len(docs) == 1

    def test_missing_dir_raises(self):
        with pytest.raises(DocumentLoadError):
            load_documents_from_dir("no_such_dir")
