"""Metadata 模块测试：知识引用提取与 ChromaDB 兼容规范化。"""

from __future__ import annotations

from app.rag.metadata import (
    enrich_document_metadata,
    extract_knowledge_metadata,
    normalize_metadata,
)
from app.rag.schemas import Document


class TestExtractKnowledgeMetadata:
    def test_extract_cwe(self):
        out = extract_knowledge_metadata("CWE-89 和 cwe-79 相关")
        assert out["cwe_id"] == ["CWE-79", "CWE-89"]

    def test_extract_cve(self):
        out = extract_knowledge_metadata("参考 CVE-2024-12345 与 CVE-2021_44228")
        assert "CVE-2024-12345" in out["cve_id"]
        assert "CVE-2021-44228" in out["cve_id"]

    def test_extract_owasp(self):
        out = extract_knowledge_metadata("OWASP A03:2021 Injection 与 A01:2021")
        assert "A01:2021" in out["owasp_id"]
        assert "A03:2021" in out["owasp_id"]

    def test_no_match_returns_empty(self):
        out = extract_knowledge_metadata("普通文本，无编号")
        assert "cwe_id" not in out
        assert "cve_id" not in out


class TestNormalizeMetadata:
    def test_supported_types_kept(self):
        meta = {"a": " str ", "b": 1, "c": 1.5, "d": True}
        out = normalize_metadata(meta)
        assert out["a"] == "str"  # 去除首尾空白
        assert out["b"] == 1
        assert out["c"] == 1.5
        assert out["d"] is True

    def test_none_and_empty_removed(self):
        out = normalize_metadata({"a": None, "b": "", "c": "  ", "d": "ok"})
        assert "a" not in out
        assert "b" not in out
        assert "c" not in out
        assert out["d"] == "ok"

    def test_list_kept_dict_downgraded(self):
        out = normalize_metadata({"tags": ["a", " b "], "complex": {"x": 1}})
        assert out["tags"] == ["a", "b"]
        assert isinstance(out["complex"], str)  # 复杂对象降级为字符串

    def test_input_not_mutated(self):
        meta = {"a": None, "b": "x"}
        original = dict(meta)
        normalize_metadata(meta)
        assert meta == original


class TestEnrichDocument:
    def test_enrich_adds_cwe_from_content(self):
        doc = Document(
            page_content="CWE-502 不安全反序列化。",
            metadata={"document_name": "a.md"},
        )
        enriched = enrich_document_metadata(doc)
        assert enriched.metadata["cwe_id"] == ["CWE-502"]

    def test_enrich_does_not_overwrite(self):
        doc = Document(
            page_content="CWE-79 内容",
            metadata={"document_name": "a.md", "cwe_id": ["CWE-89"]},
        )
        enriched = enrich_document_metadata(doc)
        assert enriched.metadata["cwe_id"] == ["CWE-89"]
