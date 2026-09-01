"""Reranker 重排序模块（Phase 1 后期优化项，此处提供轻量实现）。

设计：Reranker 为抽象基类，可替换为 BGE-Reranker / Cross-Encoder 等强模型。
当前实现 SimpleKeywordReranker：基于查询词与 Chunk 的词汇重叠度打分，
与向量相似度得分加权，缓解"向量召回但关键词不相关"的问题。
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import List, Sequence

from .vector_store import RetrievedChunk


class Reranker(ABC):
    """重排序器抽象基类。"""

    @abstractmethod
    def rerank(self, query: str, chunks: Sequence[RetrievedChunk]) -> List[RetrievedChunk]:
        """按与 query 的相关性对 chunks 重新排序，返回新列表。"""


class SimpleKeywordReranker(Reranker):
    """关键词重叠 + 向量得分加权重排。

    score_final = w * vec_score + (1 - w) * keyword_score
    keyword_score = 匹配关键词数 / 查询关键词总数
    """

    def __init__(self, vector_weight: float = 0.6, min_token_len: int = 2) -> None:
        self.vector_weight = vector_weight
        self.min_token_len = min_token_len

    def rerank(self, query: str, chunks: Sequence[RetrievedChunk]) -> List[RetrievedChunk]:
        query_tokens = self._tokenize(query)
        if not query_tokens:
            return list(chunks)

        scored: List[tuple[float, RetrievedChunk]] = []
        for chunk in chunks:
            chunk_tokens = set(self._tokenize(chunk.page_content))
            if not chunk_tokens:
                scored.append((chunk.score, chunk))
                continue
            hit = sum(1 for t in query_tokens if t in chunk_tokens)
            keyword_score = hit / len(query_tokens)
            final = self.vector_weight * chunk.score + (1 - self.vector_weight) * keyword_score
            scored.append((final, chunk))

        scored.sort(key=lambda x: x[0], reverse=True)
        result = [chunk for _, chunk in scored]
        # 回填加权后的分数
        for i, (final, chunk) in enumerate(scored):
            result[i] = RetrievedChunk(
                page_content=chunk.page_content,
                metadata=chunk.metadata,
                score=round(final, 4),
                distance=chunk.distance,
            )
        return result

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        tokens: List[str] = []
        # CJK 双字组合（简单 bigram）与 ASCII 词
        cjk_chars = re.findall(r"[\u4e00-\u9fff\u3400-\u4dbf]", text)
        for i in range(len(cjk_chars) - 1):
            tokens.append(cjk_chars[i] + cjk_chars[i + 1])
        tokens.extend(re.findall(r"[A-Za-z0-9_]{3,}", text.lower()))
        return tokens
