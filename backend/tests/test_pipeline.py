"""端到端管线测试：load -> clean -> enrich -> split -> normalize。"""

from __future__ import annotations

import json

from app.rag import (
    SemanticRecursiveTextSplitter,
    TextCleaner,
    load_documents_from_dir,
)
from app.rag.metadata import enrich_documents_metadata, normalize_metadata


def test_end_to_end_pipeline(fixtures_dir, tmp_path):
    """使用少量 fixtures 数据跑完整链路，验证产物可落盘。"""
    # 1. 加载
    docs = load_documents_from_dir(fixtures_dir)
    assert docs, "至少加载一个 Document"

    # 2. 清洗
    docs = TextCleaner().clean_documents(docs)

    # 3. Metadata 增强
    docs = enrich_documents_metadata(docs)

    # 4. 分割
    splitter = SemanticRecursiveTextSplitter(chunk_size=300, chunk_overlap=50)
    chunks = splitter.split_documents(docs)
    assert chunks, "至少生成一个 Chunk"

    # 5. 规范化 + 落盘（JSON Lines）
    output = tmp_path / "chunks.jsonl"
    with output.open("w", encoding="utf-8") as f:
        for chunk in chunks:
            record = {
                "page_content": chunk.page_content,
                "metadata": normalize_metadata(chunk.metadata),
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    # 回读验证
    lines = output.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == len(chunks)
    first = json.loads(lines[0])
    assert first["page_content"]
    assert first["metadata"]["document_name"]
    assert "chunk_id" in first["metadata"]
    assert "chunk_index" in first["metadata"]
    assert "token_count" in first["metadata"]


def test_chunks_retain_source_traceability(fixtures_dir):
    """每个 Chunk 都应保留来源信息（source / document_name / category）。"""
    docs = load_documents_from_dir(fixtures_dir)
    chunks = SemanticRecursiveTextSplitter(chunk_size=300, chunk_overlap=50).split_documents(docs)
    for chunk in chunks:
        assert chunk.metadata["source"]
        assert chunk.metadata["document_name"]
        assert chunk.metadata["category"]
        assert chunk.metadata["file_type"]
