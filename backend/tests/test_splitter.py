"""文本分割模块测试。

重点验证：
1. 能生成多个 Chunk；
2. 语义结构基本完整（标题 / 描述 / 代码示例尽量不拆散）；
3. 代码块不被从中切开；
4. Chunk metadata 正确保留与扩展。
"""

from __future__ import annotations

import pytest

from app.rag.schemas import Document
from app.rag.splitter import SemanticRecursiveTextSplitter, estimate_tokens

#: 构造一个足够长、含多个标题与代码块的知识文档
LONG_DOC = """# 测试知识文档

> CWE-89

## 漏洞描述

SQL 注入是 Web 应用最常见的注入类漏洞之一，攻击者通过拼接不可信输入
改变查询语义，实现数据窃取、篡改与认证绕过。

SQL 注入的成因包括字符串拼接查询、缺少参数化、数据库权限过高。

## 漏洞影响

- 数据泄露
- 数据篡改
- 认证绕过

## 检测方法

代码审计搜索拼接模式，动态测试注入单引号与布尔载荷观察响应差异。

## 修复方法

使用参数化查询（PreparedStatement），将数据与 SQL 结构分离；
数据库账户遵循最小权限原则；隐藏错误详情避免注入探测。

## 代码示例

### 漏洞代码（Java）

```java
String id = request.getParameter("id");
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id=" + id);
```

### 安全代码（Java）

```java
String id = request.getParameter("id");
PreparedStatement ps = connection.prepareStatement(
    "SELECT * FROM users WHERE id=?");
ps.setString(1, id);
```

## 参考资料

- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- OWASP: https://owasp.org
"""


@pytest.fixture(scope="module")
def splitter() -> SemanticRecursiveTextSplitter:
    return SemanticRecursiveTextSplitter(chunk_size=300, chunk_overlap=50)


def make_doc() -> Document:
    return Document(
        page_content=LONG_DOC,
        metadata={"document_name": "test.md", "category": "owasp_cwe", "cwe_id": ["CWE-89"]},
    )


class TestEstimateTokens:
    def test_cjk_token_estimation(self):
        assert estimate_tokens("") == 0
        assert estimate_tokens("中文文本") >= 4
        assert estimate_tokens("hello world") >= 2

    def test_estimate_grows_with_length(self):
        assert estimate_tokens("a" * 100) >= estimate_tokens("a" * 50)


class TestSplitBasics:
    def test_generates_multiple_chunks(self, splitter):
        chunks = splitter.split_document(make_doc())
        assert len(chunks) >= 2

    def test_chunk_size_within_reasonable_range(self, splitter):
        """Chunk token 数不应远超目标大小。"""
        for chunk in splitter.split_document(make_doc()):
            assert chunk.metadata["token_count"] <= splitter.chunk_size * 1.5

    def test_all_content_preserved(self, splitter):
        """分割后所有正文内容都应保留（拼接后仍包含原文关键信息）。"""
        chunks = splitter.split_document(make_doc())
        joined = "\n".join(c.page_content for c in chunks)
        for keyword in ("CWE-89", "PreparedStatement", "漏洞描述", "检测方法"):
            assert keyword in joined

    def test_overlap_param_validated(self):
        with pytest.raises(ValueError):
            SemanticRecursiveTextSplitter(chunk_size=100, chunk_overlap=200)


class TestSemanticPreservation:
    def test_code_block_not_split_in_middle(self, splitter):
        """代码块（围栏内）不得被从中切开。"""
        for chunk in splitter.split_document(make_doc()):
            content = chunk.page_content
            # 若 chunk 含代码块，围栏必须成对出现（``` 出现偶数次）
            if "```" in content:
                assert content.count("```") % 2 == 0, "代码块被从中切开"
                # 关键代码行保持完整
                assert (
                    'ResultSet rs = stmt.executeQuery' in content
                    or "PreparedStatement ps" in content
                )

    def test_section_in_metadata(self, splitter):
        """Chunk 应带语义 Section 信息。"""
        chunks = splitter.split_document(make_doc())
        sections = {c.metadata.get("section") for c in chunks}
        assert sections, "至少一个 Chunk 应包含 section"
        assert any(s is not None for s in sections)

    def test_chunk_id_unique_and_stable(self, splitter):
        chunks = splitter.split_document(make_doc())
        ids = [c.metadata["chunk_id"] for c in chunks]
        assert len(ids) == len(set(ids))
        assert all(chunk.metadata["chunk_index"] == i for i, chunk in enumerate(chunks))


class TestMetadataPreservation:
    def test_base_metadata_kept(self, splitter):
        for chunk in splitter.split_document(make_doc()):
            assert chunk.metadata["document_name"] == "test.md"
            assert chunk.metadata["category"] == "owasp_cwe"
            assert chunk.metadata["cwe_id"] == ["CWE-89"]

    def test_chunk_metadata_extended(self, splitter):
        chunk = splitter.split_document(make_doc())[0]
        for key in ("chunk_index", "chunk_id", "token_count"):
            assert key in chunk.metadata


class TestEdgeCases:
    def test_short_text_single_chunk(self):
        splitter = SemanticRecursiveTextSplitter(chunk_size=300, chunk_overlap=50)
        doc = Document(page_content="CWE-89 是 SQL 注入。", metadata={"document_name": "s.md"})
        chunks = splitter.split_document(doc)
        assert len(chunks) == 1
        assert "CWE-89" in chunks[0].page_content

    def test_empty_text(self):
        splitter = SemanticRecursiveTextSplitter()
        assert splitter.split_text("") == []
        assert splitter.split_text("   ") == []

    def test_split_documents_batch(self, splitter):
        docs = [make_doc(), Document(page_content="CWE-79 XSS 短文档。", metadata={"document_name": "b.md"})]
        chunks = splitter.split_documents(docs)
        assert len(chunks) >= 2
        names = {c.metadata["document_name"] for c in chunks}
        assert names == {"test.md", "b.md"}
