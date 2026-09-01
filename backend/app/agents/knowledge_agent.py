"""Knowledge Agent：从 RAG 知识库获取安全知识（毕设路线 8）。

工作流程：
    漏洞问题 → Query 构造 → Embedding → ChromaDB → 相似度检索
    → Metadata 过滤 → Top-K 知识 → 返回审计结果
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..rag.retriever import Retriever, get_default_retriever
from ..rag.vector_store import RetrievedChunk
from .base import AgentContext, BaseAgent

logger = logging.getLogger(__name__)


class KnowledgeAgent(BaseAgent):
    """知识检索 Agent。"""

    name = "knowledge_agent"

    def __init__(self, retriever: Optional[Retriever] = None, **kwargs) -> None:
        super().__init__(**kwargs)
        # 延迟初始化，避免导入时构建向量库
        self._retriever = retriever

    @property
    def retriever(self) -> Retriever:
        if self._retriever is None:
            self._retriever = get_default_retriever()
        return self._retriever

    def _execute(self, context: AgentContext, **kwargs) -> Dict[str, Any]:
        query = kwargs.get("query") or context.get("query", "")
        cwe_id = kwargs.get("cwe_id") or context.get("cwe_id")
        if not query and not cwe_id:
            return {"query": "", "chunks": [], "count": 0}

        top_k = kwargs.get("top_k") or context.get("top_k", 5)
        metadata_filter = kwargs.get("metadata_filter") or context.get("metadata_filter")

        if cwe_id:
            chunks = self.retriever.search_by_cwe(cwe_id, top_k=top_k)
        else:
            chunks = self.retriever.retrieve(
                query, top_k=top_k, metadata_filter=metadata_filter
            )

        return {
            "query": query,
            "count": len(chunks),
            "chunks": [c.to_dict() for c in chunks],
        }

    def format_knowledge(self, chunks: List[RetrievedChunk], max_chars: int = 4000) -> str:
        """将检索结果格式化为供 LLM 使用的知识文本。"""
        if not chunks:
            return "（无相关知识）"
        parts: List[str] = []
        for i, c in enumerate(chunks, 1):
            meta = c.metadata
            header = (
                f"[{i}] score={c.score} "
                f"来源={meta.get('document_name', '?')} "
                f"CWE={meta.get('cwe_id', '?')} "
                f"分类={meta.get('category', '?')}"
            )
            body = c.page_content[:max_chars // max(1, len(chunks))]
            parts.append(f"{header}\n{body}")
        return "\n\n".join(parts)

    def format_knowledge_from_dict(
        self, chunks: List[Dict[str, Any]], max_chars: int = 4000
    ) -> str:
        """将 dict 形式的检索结果格式化为知识文本。"""
        if not chunks:
            return "（无相关知识）"
        parts: List[str] = []
        for i, c in enumerate(chunks, 1):
            meta = c.get("metadata", {})
            header = (
                f"[{i}] score={c.get('score', 0)} "
                f"来源={meta.get('document_name', '?')} "
                f"CWE={meta.get('cwe_id', '?')} "
                f"分类={meta.get('category', '?')}"
            )
            body = (c.get("page_content") or "")[: max_chars // max(1, len(chunks))]
            parts.append(f"{header}\n{body}")
        return "\n\n".join(parts)
