"""检索测试 CLI：输入安全问题，检索知识库并展示 Top-K 结果。

用法：
    python scripts/retrieval/search_knowledge.py "Java 如何防止 SQL 注入"
    python scripts/retrieval/search_knowledge.py "什么是SSRF" --top-k 3
    python scripts/retrieval/search_knowledge.py "CWE-89" --filter '{"cwe_id": {"$in": ["CWE-89"]}}'
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.config import setup_logging  # noqa: E402
from app.rag.retriever import get_default_retriever  # noqa: E402


def main() -> None:
    setup_logging()
    parser = argparse.ArgumentParser(description="RAG 知识检索测试")
    parser.add_argument("query", help="安全问题查询，如：Java 如何防止 SQL 注入")
    parser.add_argument("--top-k", type=int, default=None, help="返回条数")
    parser.add_argument("--filter", type=str, default=None, help="Metadata 过滤 JSON")
    parser.add_argument("--no-rerank", action="store_true", help="关闭重排")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出")
    args = parser.parse_args()

    retriever = get_default_retriever(top_k=args.top_k)
    metadata_filter = json.loads(args.filter) if args.filter else None
    chunks = retriever.retrieve(
        args.query,
        top_k=args.top_k,
        metadata_filter=metadata_filter,
        rerank=False if args.no_rerank else None,
    )

    if args.json:
        print(json.dumps([c.to_dict() for c in chunks], ensure_ascii=False, indent=2))
        return

    print(f"\n查询: {args.query}\n命中 {len(chunks)} 条：\n" + "-" * 60)
    for i, c in enumerate(chunks, 1):
        meta = c.metadata
        print(f"[{i}] score={c.score} | cwe={meta.get('cwe_id')} | cat={meta.get('category')} | section={meta.get('section')}")
        print(f"    来源: {meta.get('document_name')}")
        preview = c.page_content.replace("\n", " ")[:120]
        print(f"    内容: {preview}\n")


if __name__ == "__main__":
    main()
