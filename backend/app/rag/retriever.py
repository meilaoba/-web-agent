"""Retriever 检索模块。

完整检索链路（毕设路线 20）：
    Query
      ↓ Embedding
    Dense Vector Search（ChromaDB）
      ↓ Metadata Filter（可选）
    Top-K 召回
      ↓ Reranker（可选）
    Top-N 知识
      ↓ LLM

增强：关键词兜底检索。
当知识库数据规模大（如 CNNVD 占绝大多数）或查询为缩写/短词时，
向量检索可能被无关数据淹没（Hashing 等轻量 Embedding 语义匹配弱）。
此时从查询提取关键词（含安全术语映射），用 ChromaDB 正文过滤直接召回
相关 Chunk，与向量结果融合，保证"什么是SSRF"这类查询能命中 SSRF 知识。
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Sequence

from .embedding import EmbeddingProvider, get_embedding_provider
from .reranker import Reranker, SimpleKeywordReranker
from .vector_store import ChromaVectorStore, RetrievedChunk

logger = logging.getLogger(__name__)

#: 常见安全术语映射（查询扩展）：缩写/英文 -> 中英文变体
SECURITY_TERM_MAP: Dict[str, List[str]] = {
    "ssrf": ["ssrf", "服务端请求伪造", "server-side request forgery", "伪造请求"],
    "xss": ["xss", "跨站脚本", "cross-site scripting"],
    "sqli": ["sqli", "sql 注入", "sql injection"],
    "sql": ["sql", "注入"],
    "注入": ["注入", "injection"],
    "命令注入": ["命令注入", "command injection", "rce"],
    "rce": ["rce", "远程代码执行", "命令注入"],
    "文件上传": ["文件上传", "file upload"],
    "路径遍历": ["路径遍历", "path traversal", "目录穿越", "directory traversal"],
    "目录穿越": ["目录穿越", "路径遍历", "path traversal"],
    "csrf": ["csrf", "跨站请求伪造", "cross-site request forgery"],
    "xxe": ["xxe", "xml 外部实体", "xml external entity", "外部实体注入"],
    "反序列化": ["反序列化", "deserialization", "pickle"],
    "pickle": ["pickle", "反序列化", "deserialization"],
    "认证": ["认证", "authentication", "越权", "access control"],
    "越权": ["越权", "授权", "access control", "broken access control"],
    "授权": ["授权", "access control", "越权"],
    "cwe": ["cwe"],
    "cve": ["cve"],
}

#: 无意义的查询词（过滤）
_STOPWORDS = {
    "什么", "怎么", "如何", "为什么", "哪些", "一个", "一下", "是", "的", "了",
    "在", "我", "你", "他", "它", "这", "那", "吗", "呢", "啊", "请", "介绍",
    "what", "how", "why", "which", "is", "are", "the", "a", "an", "to", "of",
    "for", "and", "or", "in", "on",
}


class Retriever:
    """RAG 检索器：封装 Embedding -> 向量检索 -> 关键词兜底 -> 过滤 -> 重排。"""

    def __init__(
        self,
        vector_store: ChromaVectorStore,
        embedding_provider: Optional[EmbeddingProvider] = None,
        reranker: Optional[Reranker] = None,
        default_top_k: int = 5,
    ) -> None:
        self.vector_store = vector_store
        self.embedding_provider = embedding_provider or get_embedding_provider()
        self.reranker = reranker
        self.default_top_k = default_top_k

    def retrieve(
        self,
        query: str,
        top_k: Optional[int] = None,
        metadata_filter: Optional[Dict[str, Any]] = None,
        where_document: Optional[Dict[str, Any]] = None,
        *,
        rerank: Optional[bool] = None,
        initial_pool: int = 20,
        keyword_fallback: bool = True,
    ) -> List[RetrievedChunk]:
        """执行检索。

        Args:
            query: 用户问题（安全相关问题，如 "什么是SSRF"）。
            top_k: 最终返回条数（默认 settings.retrieval_top_k）。
            metadata_filter: ChromaDB metadata 过滤。
            where_document: 文档内容过滤。
            rerank: 是否重排（None 表示按配置）。
            initial_pool: 重排前向量召回的候选池大小。
            keyword_fallback: 是否启用关键词兜底（默认开启）。

        Returns:
            按最终相关性排序的 RetrievedChunk 列表。
        """
        k = top_k or self.default_top_k
        pool = max(initial_pool, k)
        query_vec = self.embedding_provider.embed_query(query)

        # 1. 向量召回候选池（Dense Vector Search）
        candidates = self.vector_store.query(
            query_vec,
            top_k=pool,
            where=metadata_filter,
            where_document=where_document,
        )
        logger.debug("向量召回 %d 条（pool=%d）", len(candidates), pool)

        # 2. 关键词兜底：命中关键词的 Chunk 优先（解决短查询/缩写/数据淹没问题）
        #    用户显式传了 metadata_filter / where_document 时为精确过滤，跳过兜底
        if keyword_fallback and not metadata_filter and not where_document:
            keyword_chunks = self._keyword_retrieve(query, top_k=k)
            if keyword_chunks:
                candidates = _merge_unique(keyword_chunks + candidates)
                logger.debug("关键词兜底命中 %d 条，融合后共 %d 条", len(keyword_chunks), len(candidates))

        # 3. 重排（可选）
        use_rerank = self.reranker is not None if rerank is None else rerank
        if use_rerank and self.reranker is not None and candidates:
            candidates = self.reranker.rerank(query, candidates)
            logger.debug("重排完成: %d -> %d 条", len(candidates), min(k, len(candidates)))

        # 4. 截断 Top-K
        return candidates[:k]

    # ---------- 关键词兜底 ----------
    #: 自建知识分类（优先于海量 CNNVD 数据召回）
    CURATED_CATEGORIES = ("owasp_cwe", "owasp_top10", "quick_reference", "raw")
    #: 关键词兜底性能上限：最多处理的关键词数
    KEYWORD_LIMIT = 3
    #: 关键词兜底性能上限：每个关键词最多的大小写变体数（大写 + 小写）
    KEYWORD_VARIANTS = 2

    def _keyword_retrieve(self, query: str, top_k: int) -> List[RetrievedChunk]:
        """从查询提取关键词（受限数量与变体），检索相关知识 Chunk。

        设计特点：
        1. 优先检索自建知识类别（owasp_cwe/owasp_top10/quick_reference）；
        2. 按"自建知识优先 + 命中关键词次数"排序——避免海量 CNNVD 把
           核心安全知识（如 xss.md）淹没。

        性能优化（两级检索，替代纯 $contains 全表扫描）：
        1. 快速路径：入库时已写入 keyword_* 元数据（见 build_chunk_keywords），
           用 metadata $or 精确过滤，仅 1~2 次查询，远快于全表扫描；
        2. 兜底路径：快速路径完全未命中（旧数据）时，先用 $contains 补自建知识，
           再补全量；快速路径已有命中但不足 top_k 时，直接补全量（避免重复扫描）；
           关键词 <= KEYWORD_LIMIT、变体 <= KEYWORD_VARIANTS，达到目标即提前结束。
        """
        keywords = extract_keywords(query)[: self.KEYWORD_LIMIT]
        if not keywords:
            return []
        collected: Dict[str, RetrievedChunk] = {}
        hit_counts: Dict[str, int] = {}

        def collect(chunks) -> None:
            for c in chunks:
                key = c.metadata.get("chunk_id") or c.page_content[:60]
                if key not in collected:
                    collected[key] = c
                hit_counts[key] = hit_counts.get(key, 0) + 1

        def variants(kw: str) -> List[str]:
            """有限大小写变体：大写 + 小写（覆盖文档常见写法，去重保序）。"""
            return list(dict.fromkeys([kw.upper(), kw]))

        curated_where = {"category": {"$in": list(self.CURATED_CATEGORIES)}}

        # 1) 快速路径：metadata 关键词精确过滤（新入库数据含 keyword_*）
        collect(self.vector_store.get_by_keywords(
            keywords, limit=top_k * 3, where=curated_where))
        if len(collected) < top_k * 3:
            collect(self.vector_store.get_by_keywords(keywords, limit=top_k * 3))

        # 2) 兜底路径：$contains 补充（旧数据无 keyword_*，或快速路径命中不足 top_k）
        if len(collected) < top_k:
            if len(collected) == 0:
                # 快速路径完全未命中（旧数据）：先补自建知识小集合
                for kw in keywords:
                    for variant in variants(kw):
                        collect(self.vector_store.get_by_document_contains(
                            variant, limit=top_k * 2, where=curated_where))
                        if len(collected) >= top_k * 6:
                            break
                    if len(collected) >= top_k * 6:
                        break
            # 再补全量（CNNVD 等）；快速路径已命中时跳过 curated 重复扫描
            for kw in keywords:
                for variant in variants(kw):
                    collect(self.vector_store.get_by_document_contains(
                        variant, limit=top_k * 2))
                    if len(collected) >= top_k * 6:
                        break
                if len(collected) >= top_k * 6:
                    break

        def sort_key(c: RetrievedChunk) -> tuple:
            cat = c.metadata.get("category", "")
            curated = 0 if cat in self.CURATED_CATEGORIES else 1
            hits = hit_counts.get(c.metadata.get("chunk_id") or c.page_content[:60], 0)
            return (curated, -hits)

        ranked = sorted(collected.values(), key=sort_key)
        logger.debug("关键词提取: %s -> 召回 %d 条", keywords, len(ranked))
        return ranked[: top_k * 4]




    def retrieve_with_query_embedding(
        self,
        query: str,
        top_k: int = 5,
    ) -> List[float]:
        """返回查询向量（供上层展示 / 实验使用）。"""
        return self.embedding_provider.embed_query(query)

    # ---------- 便捷方法 ----------
    def search_by_vulnerability(self, vuln_type: str, top_k: int = 5) -> List[RetrievedChunk]:
        """按漏洞类型关键词检索（审计场景常用入口）。"""
        return self.retrieve(vuln_type, top_k=top_k)

    def search_by_cwe(self, cwe_id: str, top_k: int = 5) -> List[RetrievedChunk]:
        """按 CWE 编号检索。

        说明：ChromaDB where 过滤对数组字段不支持"包含"语义，而安全知识
        Chunk 正文均标注 CWE 编号，故使用 where_document $contains 过滤正文；
        标量字段（category/source 等）仍可用 metadata_filter 精确过滤。
        """
        return self.retrieve(
            cwe_id,
            top_k=top_k,
            where_document={"$contains": cwe_id},
        )


def extract_keywords(query: str) -> List[str]:
    """从查询提取关键词（ASCII 词 + 中文术语映射扩展）。

    - ASCII 词：ssrf / xss / sql 等（≥3 字符，小写化）
    - 中文：匹配安全术语表，扩展出中英文变体
    - 过滤停用词
    """
    q = query.lower()
    keywords: List[str] = []

    # 1. ASCII 词
    for word in re.findall(r"[a-z0-9_-]{3,}", q):
        if word not in _STOPWORDS:
            keywords.append(word)
            # 术语扩展
            keywords.extend(SECURITY_TERM_MAP.get(word, []))

    # 2. 中文术语匹配（子串匹配术语表）
    for term, variants in SECURITY_TERM_MAP.items():
        if term in q:
            keywords.extend(variants)

    # 3. 去重保序，过滤停用词与单字符
    result: List[str] = []
    seen: set = set()
    for kw in keywords:
        kw = kw.strip().lower()
        if not kw or len(kw) < 2 or kw in _STOPWORDS or kw in seen:
            continue
        seen.add(kw)
        result.append(kw)
    return result


def _case_variants(keyword: str) -> List[str]:
    """生成大小写变体（ChromaDB 正文过滤区分大小写）。"""
    variants = {keyword, keyword.lower(), keyword.upper(), keyword.capitalize()}
    # 首字母大写（常见专名写法，如 Ssrf -> SSRF）
    return sorted(variants, key=len, reverse=True)


def _merge_unique(chunks: Sequence[RetrievedChunk]) -> List[RetrievedChunk]:
    """按 chunk_id（或内容前缀）去重合并，保持顺序。"""
    merged: List[RetrievedChunk] = []
    seen: set = set()
    for c in chunks:
        key = c.metadata.get("chunk_id") or c.page_content[:60]
        if key in seen:
            continue
        seen.add(key)
        merged.append(c)
    return merged


#: 进程内 Retriever 缓存（按关键配置区分，避免每次请求重复构建向量库客户端）
_RETRIEVER_CACHE: Dict[tuple, Retriever] = {}


def get_default_retriever(top_k: int | None = None) -> Retriever:
    """工厂：按配置构建默认 Retriever（进程内缓存，避免每次请求重复初始化）。

    缓存键为影响向量库的关键配置（目录/集合/Embedding/重排开关/维度），
    配置变化时自动重建；测试通过环境变量切换临时目录不会命中旧实例。
    """
    from ..config import settings

    key = (
        str(settings.chroma_dir),
        settings.chroma_collection,
        settings.embedding_provider,
        settings.rerank_enabled,
        settings.embedding_dimension,
    )
    if key in _RETRIEVER_CACHE:
        return _RETRIEVER_CACHE[key]

    store = ChromaVectorStore(
        settings.chroma_dir,
        settings.chroma_collection,
        embedding_dimension=settings.embedding_dimension,
    )
    reranker = SimpleKeywordReranker() if settings.rerank_enabled else None
    retriever = Retriever(
        vector_store=store,
        embedding_provider=get_embedding_provider(),
        reranker=reranker,
        default_top_k=top_k or settings.retrieval_top_k,
    )
    _RETRIEVER_CACHE[key] = retriever
    return retriever


def build_chunk_keywords(
    page_content: str,
    metadata: Dict[str, Any],
    limit: int = 12,
) -> List[str]:
    """为单个 Chunk 生成检索关键词（写入 metadata.keyword_* 供快速过滤）。

    关键词来源（统一小写去重）：
    1. metadata 的 title / vulnerability_type / document_name / category /
       cnnvd_id / cve_id 等字段；
    2. 正文关键词（复用 extract_keywords 的安全术语扩展）；
    3. cwe_id（可能为 "; " 分隔字符串或列表）。

    返回最多 limit 个关键词。调用方负责写入 metadata.keyword_0..N。
    """
    sources: List[str] = []
    for key in ("title", "vulnerability_type", "document_name", "category",
                "cnnvd_id", "cve_id"):
        value = metadata.get(key)
        if isinstance(value, (list, tuple)):
            sources.extend(str(x) for x in value)
        elif value:
            sources.append(str(value))
    text = " ".join(sources) + "\n" + (page_content or "")
    keywords = extract_keywords(text)

    cwes = metadata.get("cwe_id")
    if cwes:
        if isinstance(cwes, (list, tuple)):
            keywords.extend(str(x).lower() for x in cwes)
        else:
            keywords.extend(str(cwes).lower().replace(";", " ").split())

    seen: set = set()
    result: List[str] = []
    for kw in keywords:
        kw = str(kw).strip().lower()
        if not kw or kw in seen:
            continue
        seen.add(kw)
        result.append(kw)
        if len(result) >= limit:
            break
    return result

