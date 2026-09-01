# -*- coding: utf-8 -*-
"""为现有 ChromaDB 数据补充 keyword_* 元数据（不重算 embedding）。

背景：检索快速路径依赖入库时写入的 keyword_* 元数据字段；
本脚本用于为存量数据补齐该字段，使旧数据无需重新向量化即可享受快速检索。

用法：
    python scripts/data_pipeline/add_keywords_metadata.py
    python scripts/data_pipeline/add_keywords_metadata.py --batch 200
"""
from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.config import setup_logging  # noqa: E402
from app.rag.retriever import build_chunk_keywords  # noqa: E402
from app.rag.vector_store import KEYWORD_MAX_FIELDS, ChromaVectorStore  # noqa: E402

logger = logging.getLogger("add_keywords_metadata")


def main() -> None:
    setup_logging()
    parser = argparse.ArgumentParser(description="为现有 ChromaDB 数据补充 keyword_* 元数据")
    parser.add_argument("--collection", type=str, default=None, help="collection 名")
    parser.add_argument("--batch", type=int, default=200, help="update 批次大小")
    args = parser.parse_args()

    from app.config import settings

    store = ChromaVectorStore(settings.chroma_dir, args.collection or settings.chroma_collection)
    col = store._collection
    total = store.count()
    logger.info("知识库 chunk 总数: %d，目录: %s", total, settings.chroma_dir)

    updated = 0
    skipped = 0
    keyword_stats: Dict[int, int] = {}
    read_batch = 500
    offset = 0
    start = time.time()

    while True:
        res = col.get(limit=read_batch, offset=offset, include=["documents", "metadatas"])
        ids: List[str] = res.get("ids", [])
        docs = res.get("documents", [])
        metas = res.get("metadatas", [])
        if not ids:
            break

        updates_ids: List[str] = []
        updates_metas: List[Dict] = []
        for i, cid in enumerate(ids):
            meta = dict(metas[i]) if i < len(metas) and metas[i] else {}
            if "keyword_0" in meta:
                skipped += 1
                continue
            kws = build_chunk_keywords(str(docs[i]) if i < len(docs) else "", meta)[:KEYWORD_MAX_FIELDS]
            new_meta = dict(meta)
            for idx, kw in enumerate(kws):
                new_meta[f"keyword_{idx}"] = kw
            keyword_stats[len(kws)] = keyword_stats.get(len(kws), 0) + 1
            updates_ids.append(cid)
            updates_metas.append(new_meta)

        # 分批 update（只更新 metadata，不动 embedding；批次不超过 ChromaDB 上限 166）
        batch = max(1, min(args.batch, 100))
        for j in range(0, len(updates_ids), batch):
            chunk_ids = updates_ids[j:j + batch]
            chunk_metas = updates_metas[j:j + batch]
            col.update(ids=chunk_ids, metadatas=chunk_metas)
        updated += len(updates_ids)
        offset += len(ids)
        if len(ids) < read_batch:
            break

    logger.info("迁移完成: 更新 %d 条, 跳过(已含 keyword_0) %d 条, 耗时 %.1fs", updated, skipped, time.time() - start)
    if keyword_stats:
        top = sorted(keyword_stats.items(), key=lambda x: -x[1])[:5]
        logger.info("关键词数量分布(前5): %s", top)
    store.close()


if __name__ == "__main__":
    main()
