"""知识入库脚本：将处理后的 Chunks（chunks.jsonl）向量化并写入 ChromaDB。

执行链路：
    chunks.jsonl（Phase 1 产物）
      → 加载（含原始 metadata）
      → Embedding（按配置，默认 Hashing 降级 / 可切换 BGE-M3）
      → ChromaDB（collection: security_knowledge）
      → 打印入库统计

用法：
    python scripts/data_pipeline/ingest_knowledge.py
    python scripts/data_pipeline/ingest_knowledge.py --chunks backend/data/processed/chunks.jsonl
    EMBEDDING_PROVIDER=bge_m3 python scripts/ingest_knowledge.py   # 使用真实模型
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import List

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.config import setup_logging  # noqa: E402
from app.rag.embedding import get_embedding_provider  # noqa: E402
from app.rag.schemas import Document  # noqa: E402
from app.rag.vector_store import ChromaVectorStore  # noqa: E402

logger = logging.getLogger("ingest_knowledge")


def load_chunks(path: Path) -> List[Document]:
    """读取 chunks.jsonl 为 Document 列表。"""
    docs: List[Document] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            docs.append(
                Document(
                    page_content=record.get("page_content", ""),
                    metadata=record.get("metadata", {}),
                )
            )
    return docs


def main() -> None:
    setup_logging()
    parser = argparse.ArgumentParser(description="将知识 Chunk 向量化并入 ChromaDB")
    parser.add_argument("--chunks", type=str, default=None, help="chunks.jsonl 路径")
    parser.add_argument("--collection", type=str, default=None, help="ChromaDB collection 名")
    parser.add_argument("--reset", action="store_true", help="入库前清空集合")
    args = parser.parse_args()

    from app.config import settings

    chunks_path = Path(args.chunks) if args.chunks else settings.data_processed_dir / "chunks.jsonl"
    if not chunks_path.is_file():
        logger.error("Chunk 文件不存在: %s（请先运行 scripts/data_pipeline/build_knowledge_base.py）", chunks_path)
        sys.exit(1)

    # 1. 加载 Chunk
    docs = load_chunks(chunks_path)
    docs = _with_keywords(docs)
    logger.info("加载 Chunk: %d 条（%s）", len(docs), chunks_path)
    if not docs:
        logger.error("Chunk 文件为空，无法入库")
        sys.exit(1)

    # 2. 向量化
    provider = get_embedding_provider()
    logger.info("向量化 %d 条文本（provider=%s, dim=%d）...", len(docs), type(provider).__name__, provider.dimension)
    start = time.time()
    embeddings = provider.embed_texts([d.page_content for d in docs])
    logger.info("向量化完成，耗时 %.2fs", time.time() - start)

    # 3. 入库
    store = ChromaVectorStore(
        settings.chroma_dir,
        args.collection or settings.chroma_collection,
        embedding_dimension=provider.dimension,
    )
    if args.reset:
        store.reset()
    added = store.add_documents(docs, embeddings)
    logger.info("入库完成: +%d 条，集合现有 %d 条（目录: %s）", added, store.count(), settings.chroma_dir)
    # 关键：显式关闭客户端，触发 HNSW 索引落盘（0.5.x 异步 compaction）
    store.close()
    # 诊断：打印完整目录树
    import os

    logger.info("诊断: close 后 chroma 目录完整内容:")
    for root, dirs, files in os.walk(settings.chroma_dir):
        for fn in sorted(files):
            p = os.path.join(root, fn)
            logger.info("   %s (%d bytes)", p, os.path.getsize(p))


if __name__ == "__main__":
    main()
