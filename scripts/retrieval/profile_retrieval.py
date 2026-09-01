# -*- coding: utf-8 -*-
"""RAG 检索性能定位脚本。

用途：量化检索链路各阶段耗时，定位瓶颈。
  - 知识库规模
  - 各查询的：embed_query / 向量召回 / 关键词兜底（含 $contains 调用次数与耗时）/ 完整 retrieve

用法：
    python scripts/retrieval/profile_retrieval.py
    python scripts/retrieval/profile_retrieval.py --queries "SSRF,SQL注入,CWE-89"
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.config import settings  # noqa: E402
from app.rag.retriever import extract_keywords, get_default_retriever  # noqa: E402

DEFAULT_QUERIES = [
    "什么是SSRF",
    "SQL注入漏洞如何检测和修复",
    "命令注入 subprocess",
    "什么是XSS 跨站脚本",
    "CWE-89 SQL注入",
    "pickle 反序列化 漏洞",
]


def profile_query(query: str, retriever):
    """对单个查询做分段计时。"""
    print(f"\n=== 查询: {query!r} ===")
    store = retriever.vector_store

    keywords = extract_keywords(query)

    # 1. embed_query
    t0 = time.perf_counter()
    vec = retriever.embedding_provider.embed_query(query)
    t_embed = time.perf_counter() - t0

    # 2. 向量召回（pool=20，与 retrieve 默认一致）
    t0 = time.perf_counter()
    candidates = store.query(vec, top_k=20)
    t_vec = time.perf_counter() - t0

    # 3. 关键词兜底（monkey-patch 统计 $contains 调用）
    stats = {"n": 0, "total": 0.0, "max": 0.0}
    orig = store.get_by_document_contains

    def timed(keyword, limit=20, where=None):
        t0 = time.perf_counter()
        out = orig(keyword, limit=limit, where=where)
        dt = time.perf_counter() - t0
        stats["n"] += 1
        stats["total"] += dt
        stats["max"] = max(stats["max"], dt)
        return out

    store.get_by_document_contains = timed
    t0 = time.perf_counter()
    kw_chunks = retriever._keyword_retrieve(query, top_k=5)
    t_kw = time.perf_counter() - t0
    store.get_by_document_contains = orig

    # 4. 完整 retrieve
    t0 = time.perf_counter()
    result = retriever.retrieve(query, top_k=5)
    t_total = time.perf_counter() - t0

    print(f"  关键词: {keywords}")
    print(f"  embed_query      : {t_embed * 1000:9.1f} ms")
    print(f"  向量召回(pool20) : {t_vec * 1000:9.1f} ms  ({len(candidates)} 条)")
    print(f"  关键词兜底       : {t_kw * 1000:9.1f} ms  ($contains 调用 {stats['n']} 次, "
          f"累计 {stats['total'] * 1000:.1f} ms, 单次最大 {stats['max'] * 1000:.1f} ms, 召回 {len(kw_chunks)} 条)")
    print(f"  完整 retrieve    : {t_total * 1000:9.1f} ms  (返回 {len(result)} 条)")
    return {
        "query": query, "embed_ms": t_embed * 1000, "vector_ms": t_vec * 1000,
        "keyword_ms": t_kw * 1000, "contains_calls": stats["n"],
        "contains_total_ms": stats["total"] * 1000, "total_ms": t_total * 1000,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="RAG 检索性能定位")
    parser.add_argument("--queries", type=str, default=None,
                        help="逗号分隔的查询列表；缺省使用内置示例")
    args = parser.parse_args()

    queries = [q.strip() for q in args.queries.split(",")] if args.queries else DEFAULT_QUERIES
    queries = [q for q in queries if q]

    print("========== 配置 ==========")
    print(f"  chroma_dir       : {settings.chroma_dir}")
    print(f"  collection       : {settings.chroma_collection}")
    print(f"  rerank_enabled   : {settings.rerank_enabled}")
    print(f"  retrieval_top_k  : {settings.retrieval_top_k}")

    retriever = get_default_retriever()
    store = retriever.vector_store
    print(f"  知识库 chunk 数  : {store.count()}")
    print(f"  embedding        : {retriever.embedding_provider.__class__.__name__}")

    print("\n========== 分段计时 ==========")
    rows = []
    for q in queries:
        rows.append(profile_query(q, retriever))

    print("\n========== 汇总 ==========")
    for r in rows:
        print(f"  {r['query'][:24]:<26} embed={r['embed_ms']:7.1f}ms 向量={r['vector_ms']:7.1f}ms "
              f"兜底={r['keyword_ms']:7.1f}ms $contains={r['contains_calls']:3d}次 "
              f"($contains共{r['contains_total_ms']:7.1f}ms) 总={r['total_ms']:7.1f}ms")


if __name__ == "__main__":
    main()
