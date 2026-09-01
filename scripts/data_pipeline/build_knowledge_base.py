"""知识库数据处理管线（Phase 1）。

执行链路：
    data/raw（原始知识文档）
        -> 文档加载（loader）
        -> 文本清洗（cleaner）
        -> Metadata 增强（metadata）
        -> 文本分割（splitter）
    -> data/processed（Chunk 产物：chunks.jsonl + summary.json）

产物 chunks.jsonl 为 JSON Lines 格式（每行一个 Chunk）：
    {"page_content": "...", "metadata": {...}}

用法：
    python scripts/data_pipeline/build_knowledge_base.py
    python scripts/data_pipeline/build_knowledge_base.py --input-dir backend/data/raw --chunk-size 1000
    python scripts/data_pipeline/build_knowledge_base.py --no-clean
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

# 允许直接以脚本方式运行（python scripts/data_pipeline/build_knowledge_base.py）
PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.config import setup_logging  # noqa: E402
from app.rag import (  # noqa: E402
    SemanticRecursiveTextSplitter,
    TextCleaner,
    estimate_tokens,
    load_documents_from_dir,
)
from app.rag.metadata import (  # noqa: E402
    enrich_documents_metadata,
    normalize_metadata,
)

logger = logging.getLogger("build_knowledge_base")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="构建 RAG 安全知识库数据（Phase 1 管线）")
    parser.add_argument(
        "--input-dir",
        type=str,
        default=None,
        help="原始知识目录（默认 backend/data/raw）",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="产物输出目录（默认 backend/data/processed）",
    )
    parser.add_argument("--chunk-size", type=int, default=None, help="Chunk 大小（近似 token）")
    parser.add_argument("--chunk-overlap", type=int, default=None, help="Chunk 重叠（近似 token）")
    parser.add_argument("--no-clean", action="store_true", help="跳过文本清洗步骤")
    parser.add_argument(
        "--extensions",
        nargs="*",
        default=None,
        help="仅处理指定扩展名，如 --extensions md json",
    )
    return parser.parse_args()


def build(
    input_dir: Path,
    output_dir: Path,
    *,
    chunk_size: int,
    chunk_overlap: int,
    clean: bool,
    extensions: List[str] | None,
) -> Dict[str, Any]:
    """执行完整管线，返回统计信息。"""
    # 1. 文档加载
    logger.info("==> 1/4 文档加载: %s", input_dir)
    docs = load_documents_from_dir(input_dir, extensions=extensions)
    if not docs:
        raise RuntimeError(f"未从 {input_dir} 加载到任何文档，请检查数据目录")

    # 2. 文本清洗
    logger.info("==> 2/4 文本清洗（clean=%s）", clean)
    if clean:
        cleaner = TextCleaner()
        docs = cleaner.clean_documents(docs)

    # 3. Metadata 增强（提取正文中的 CWE / CVE / OWASP 引用）
    logger.info("==> 3/4 Metadata 增强")
    docs = enrich_documents_metadata(docs)

    # 4. 文本分割
    logger.info("==> 4/4 文本分割（chunk_size=%d, overlap=%d）", chunk_size, chunk_overlap)
    splitter = SemanticRecursiveTextSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
    chunks = splitter.split_documents(docs)

    # 5. Metadata 规范化（ChromaDB 兼容）+ 落盘
    output_dir.mkdir(parents=True, exist_ok=True)
    chunks_path = output_dir / "chunks.jsonl"
    total_tokens = 0
    with chunks_path.open("w", encoding="utf-8") as f:
        for chunk in chunks:
            normalized = normalize_metadata(chunk.metadata)
            total_tokens += int(normalized.get("token_count", estimate_tokens(chunk.page_content)))
            record = {"page_content": chunk.page_content, "metadata": normalized}
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    summary = _build_summary(docs, chunks, chunks_path, total_tokens)
    summary_path = output_dir / "summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    logger.info("产物写入完成: %s / %s", chunks_path, summary_path)
    return summary


def _build_summary(
    docs: List[Any], chunks: List[Any], chunks_path: Path, total_tokens: int
) -> Dict[str, Any]:
    """生成处理统计信息。"""
    by_category: Dict[str, int] = {}
    for chunk in chunks:
        cat = str(chunk.metadata.get("category", "unknown"))
        by_category[cat] = by_category.get(cat, 0) + 1

    by_section: Dict[str, int] = {}
    for chunk in chunks:
        sec = str(chunk.metadata.get("section", "none"))
        by_section[sec] = by_section.get(sec, 0) + 1

    chunk_tokens = [int(c.metadata.get("token_count", 0)) for c in chunks]
    return {
        "pipeline": "load -> clean -> enrich -> split -> normalize",
        "input_dir": str(chunks_path.parents[1] / "raw"),
        "output_file": str(chunks_path),
        "document_count": len(docs),
        "chunk_count": len(chunks),
        "total_tokens_approx": total_tokens,
        "chunk_tokens": {
            "min": min(chunk_tokens) if chunk_tokens else 0,
            "max": max(chunk_tokens) if chunk_tokens else 0,
            "avg": round(sum(chunk_tokens) / len(chunk_tokens), 1) if chunk_tokens else 0,
        },
        "chunks_by_category": dict(sorted(by_category.items())),
        "chunks_by_section": dict(sorted(by_section.items())),
    }


def main() -> None:
    setup_logging()
    args = parse_args()

    from app.config import settings

    input_dir = Path(args.input_dir) if args.input_dir else settings.data_raw_dir
    output_dir = Path(args.output_dir) if args.output_dir else settings.data_processed_dir
    chunk_size = args.chunk_size or settings.chunk_size
    chunk_overlap = args.chunk_overlap if args.chunk_overlap is not None else settings.chunk_overlap

    start = time.time()
    try:
        summary = build(
            input_dir,
            output_dir,
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
            clean=not args.no_clean,
            extensions=args.extensions,
        )
    except RuntimeError as exc:
        logger.error("%s", exc)
        sys.exit(1)

    logger.info("管线完成，耗时 %.2fs：%s", time.time() - start, summary)


if __name__ == "__main__":
    main()
