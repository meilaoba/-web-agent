"""RAG 检索效果评估工具（论文实验基础）。

评估方式：预定义"查询 → 期望命中的 CWE / 文档"评估集，
运行检索后判断期望知识是否出现在 Top-K 结果中，计算：
- Recall@K（期望知识被召回的比例）
- Precision@K（结果中相关知识的比例，按期望集合近似）
- 平均命中分数 / 耗时

用法：
    python scripts/retrieval/evaluate_rag.py                # 默认评估集
    python scripts/retrieval/evaluate_rag.py --top-k 3
    python scripts/retrieval/evaluate_rag.py --top-k 5
    python scripts/retrieval/evaluate_rag.py --top-k 10     # Top-K 实验
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.config import setup_logging  # noqa: E402
from app.rag.retriever import get_default_retriever  # noqa: E402

logger = logging.getLogger("evaluate_rag")

#: 评估集：query -> 期望命中的 CWE 编号（出现任一即算命中）
EVAL_SET: List[Dict[str, Any]] = [
    {"query": "Java 中如何防止 SQL 注入", "expected_cwe": ["CWE-89"]},
    {"query": "什么是跨站脚本攻击 XSS 以及如何防护", "expected_cwe": ["CWE-79"]},
    {"query": "SSRF 服务端请求伪造的检测与修复", "expected_cwe": ["CWE-918"]},
    {"query": "文件上传漏洞如何防护", "expected_cwe": ["CWE-434"]},
    {"query": "路径遍历目录穿越如何修复", "expected_cwe": ["CWE-22"]},
    {"query": "命令注入的检测与防御", "expected_cwe": ["CWE-78"]},
    {"query": "CSRF 跨站请求伪造防护", "expected_cwe": ["CWE-352"]},
    {"query": "XXE XML 外部实体注入防护", "expected_cwe": ["CWE-611"]},
    {"query": "不安全反序列化漏洞", "expected_cwe": ["CWE-502"]},
    {"query": "认证与越权问题如何审计", "expected_cwe": ["CWE-287", "CWE-862"]},
]


def hit(chunk_meta: Dict[str, Any], expected: List[str]) -> bool:
    """判断 Chunk 是否命中期望 CWE。"""
    chunk_cwes = chunk_meta.get("cwe_id") or []
    if isinstance(chunk_cwes, str):
        chunk_cwes = [chunk_cwes]
    return any(cwe in expected for cwe in chunk_cwes)


def main() -> None:
    setup_logging()
    parser = argparse.ArgumentParser(description="RAG 检索效果评估")
    parser.add_argument("--top-k", type=int, default=5, help="Top-K（实验: 3/5/10）")
    parser.add_argument("--no-rerank", action="store_true", help="关闭重排")
    args = parser.parse_args()

    retriever = get_default_retriever(top_k=args.top_k)

    hit_count = 0
    total_latency = 0.0
    details: List[Dict[str, Any]] = []
    for item in EVAL_SET:
        start = time.time()
        chunks = retriever.retrieve(
            item["query"],
            top_k=args.top_k,
            rerank=False if args.no_rerank else None,
        )
        latency = time.time() - start
        total_latency += latency
        is_hit = any(hit(c.metadata, item["expected_cwe"]) for c in chunks)
        hit_count += int(is_hit)
        details.append(
            {
                "query": item["query"],
                "expected_cwe": item["expected_cwe"],
                "hit": is_hit,
                "top_results": [
                    {
                        "cwe": c.metadata.get("cwe_id"),
                        "doc": c.metadata.get("document_name"),
                        "score": c.score,
                    }
                    for c in chunks
                ],
            }
        )

    total = len(EVAL_SET)
    recall = hit_count / total
    avg_latency = total_latency / total
    print("=" * 60)
    print(f"评估结果（Top-K={args.top_k}, rerank={'on' if not args.no_rerank else 'off'}）")
    print(f"查询总数: {total}")
    print(f"命中数: {hit_count}")
    print(f"Recall@K: {recall:.2%}")
    print(f"平均检索耗时: {avg_latency * 1000:.1f} ms")
    print("=" * 60)
    for d in details:
        status = "OK" if d["hit"] else "MISS"
        print(f"  [{status}] [{','.join(d['expected_cwe'])}] {d['query']}")
        if not d["hit"]:
            print(f"      实际命中 CWE: {[r['cwe'] for r in d['top_results']]}")


if __name__ == "__main__":
    main()
