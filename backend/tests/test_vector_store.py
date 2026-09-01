"""ChromaDB 向量存储与 Retriever 测试。"""

from __future__ import annotations

import pytest

from app.rag.embedding import HashingEmbeddingProvider
from app.rag.retriever import Retriever
from app.rag.schemas import Document
from app.rag.vector_store import ChromaVectorStore, RetrievedChunk, VectorStoreError


@pytest.fixture()
def store(tmp_path):
    """每个测试独立临时目录的向量库。"""
    return ChromaVectorStore(tmp_path / "chroma", "test_kb")


@pytest.fixture()
def provider() -> HashingEmbeddingProvider:
    return HashingEmbeddingProvider(dimension=128)


def make_docs() -> list[Document]:
    return [
        Document(
            page_content="CWE-89 SQL 注入：使用参数化查询 PreparedStatement 防止拼接注入。",
            metadata={
                "chunk_id": "sqli-0001",
                "source": "/data/sql_injection.md",
                "document_name": "sql_injection.md",
                "category": "owasp_cwe",
                "cwe_id": ["CWE-89"],
            },
        ),
        Document(
            page_content="CWE-79 XSS：输出转义，避免 innerHTML 注入脚本。",
            metadata={
                "chunk_id": "xss-0001",
                "source": "/data/xss.md",
                "document_name": "xss.md",
                "category": "owasp_cwe",
                "cwe_id": ["CWE-79"],
            },
        ),
        Document(
            page_content="CWE-434 文件上传：校验扩展名与内容魔数。",
            metadata={
                "chunk_id": "upload-0001",
                "source": "/data/file_upload.md",
                "document_name": "file_upload.md",
                "category": "owasp_cwe",
                "cwe_id": ["CWE-434"],
            },
        ),
    ]


class TestVectorStore:
    def test_add_and_count(self, store, provider):
        docs = make_docs()
        embeddings = provider.embed_texts([d.page_content for d in docs])
        added = store.add_documents(docs, embeddings)
        assert added == 3
        assert store.count() == 3

    def test_upsert_idempotent(self, store, provider):
        docs = make_docs()
        emb = provider.embed_texts([d.page_content for d in docs])
        store.add_documents(docs, emb)
        store.add_documents(docs, emb)  # 重复入库（同 chunk_id 覆盖）
        assert store.count() == 3

    def test_mismatched_length_raises(self, store, provider):
        with pytest.raises(VectorStoreError):
            store.add_documents(make_docs(), [[0.0] * 4])

    def test_missing_chunk_id_raises(self, store, provider):
        doc = Document(page_content="无 chunk_id 的文档", metadata={"source": "x"})
        with pytest.raises(VectorStoreError):
            store.add_documents([doc], [[0.0] * 128])

    def test_query_returns_top_k(self, store, provider):
        docs = make_docs()
        emb = provider.embed_texts([d.page_content for d in docs])
        store.add_documents(docs, emb)
        result = store.query(provider.embed_query("SQL 注入 参数化查询"), top_k=2)
        assert len(result) == 2
        assert all(isinstance(c, RetrievedChunk) for c in result)
        # 距离度量空间（cosine/l2）下分数可为负（不相似时），断言其为有限数即可
        assert all(isinstance(c.score, float) for c in result)

    def test_query_with_metadata_filter(self, store, provider):
        docs = make_docs()
        emb = provider.embed_texts([d.page_content for d in docs])
        store.add_documents(docs, emb)
        # 标量字段用 $in 精确过滤
        result = store.query(
            provider.embed_query("漏洞"),
            top_k=5,
            where={"category": {"$in": ["owasp_cwe"]}},
        )
        assert len(result) >= 1
        assert all(c.metadata["category"] == "owasp_cwe" for c in result)

    def test_query_with_where_document(self, store, provider):
        docs = make_docs()
        emb = provider.embed_texts([d.page_content for d in docs])
        store.add_documents(docs, emb)
        # 正文内容过滤（CWE 编号在正文中标注）
        result = store.query(
            provider.embed_query("漏洞"),
            top_k=5,
            where_document={"$contains": "CWE-89"},
        )
        assert len(result) >= 1
        assert all("CWE-89" in c.page_content for c in result)

    def test_reset(self, store, provider):
        docs = make_docs()
        emb = provider.embed_texts([d.page_content for d in docs])
        store.add_documents(docs, emb)
        store.reset()
        assert store.count() == 0

    def test_get_by_source(self, store, provider):
        docs = make_docs()
        emb = provider.embed_texts([d.page_content for d in docs])
        store.add_documents(docs, emb)
        found = store.get_by_source("/data/xss.md")
        assert len(found) == 1
        assert found[0]["id"] == "xss-0001"


class TestRetriever:
    def test_retrieve_semantic_hit(self, store, provider):
        docs = make_docs()
        emb = provider.embed_texts([d.page_content for d in docs])
        store.add_documents(docs, emb)
        retriever = Retriever(store, provider, default_top_k=3)
        result = retriever.retrieve("如何防止 SQL 注入", top_k=3)
        assert result
        top = result[0]
        assert "CWE-89" in (top.metadata.get("cwe_id") or [])

    def test_retrieve_with_filter(self, store, provider):
        docs = make_docs()
        emb = provider.embed_texts([d.page_content for d in docs])
        store.add_documents(docs, emb)
        retriever = Retriever(store, provider)
        result = retriever.retrieve(
            "漏洞", top_k=5, metadata_filter={"category": "owasp_cwe"}
        )
        assert len(result) >= 1
        assert all(c.metadata["category"] == "owasp_cwe" for c in result)

    def test_search_by_cwe(self, store, provider):
        docs = make_docs()
        emb = provider.embed_texts([d.page_content for d in docs])
        store.add_documents(docs, emb)
        retriever = Retriever(store, provider)
        result = retriever.search_by_cwe("CWE-79")
        assert result
        assert all("CWE-79" in (c.metadata.get("cwe_id") or []) for c in result)

    def test_empty_query_returns_empty(self, store, provider):
        retriever = Retriever(store, provider)
        assert retriever.retrieve("", top_k=3) == []
