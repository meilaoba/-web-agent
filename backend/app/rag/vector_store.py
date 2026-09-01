"""ChromaDB 向量存储模块。

封装 ChromaDB 的 Collection 操作，业务代码不直接依赖 chromadb 客户端。

Collection 结构（与毕设路线一致）：
    id        : chunk_id（全局唯一且稳定）
    document  : page_content
    embedding : 向量
    metadata  : 规范化后的元数据（含 source/cwe_id/owasp_id/category 等）

支持：
- 批量入库（add_documents）
- 向量相似度检索（query，Top-K + Metadata 过滤）
- 集合统计 / 清空 / 按源删除
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .schemas import Document

logger = logging.getLogger(__name__)


class VectorStoreError(Exception):
    """向量库操作异常。"""


#: metadata 关键词字段数量上限（keyword_0 .. keyword_11）
KEYWORD_MAX_FIELDS = 12


def _serialize_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """将 metadata 中的列表值序列化为 '; ' 分隔字符串（ChromaDB 过滤友好）。"""
    out: Dict[str, Any] = {}
    for key, value in metadata.items():
        if isinstance(value, (list, tuple)):
            out[key] = "; ".join(str(v) for v in value)
        else:
            out[key] = value
    return out


@dataclass
class RetrievedChunk:
    """检索结果单元。"""

    page_content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    score: float = 0.0
    distance: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "page_content": self.page_content,
            "metadata": self.metadata,
            "score": self.score,
            "distance": self.distance,
        }


class ChromaVectorStore:
    """ChromaDB 向量存储封装。"""

    def __init__(
        self,
        persist_dir: Path | str,
        collection_name: str = "security_knowledge",
        *,
        embedding_dimension: Optional[int] = None,
    ) -> None:
        try:
            import chromadb
        except ImportError as exc:
            raise VectorStoreError(
                "未安装 chromadb，请执行: pip install chromadb"
            ) from exc

        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self.collection_name = collection_name

        # 持久化客户端（chromadb>=0.4 推荐 PersistentClient）
        self._client = chromadb.PersistentClient(path=str(self.persist_dir))
        # 使用默认度量空间（l2），避免部分 chromadb 版本 cosine HNSW 索引加载异常
        self._collection = self._client.get_or_create_collection(
            name=collection_name,
        )
        logger.info(
            "ChromaDB 就绪: dir=%s collection=%s 现有记录=%d",
            self.persist_dir,
            collection_name,
            self._collection.count(),
        )

    # ---------- 写入 ----------
    def add_documents(
        self,
        documents: Sequence[Document],
        embeddings: Sequence[Sequence[float]],
    ) -> int:
        """批量入库 Document（要求 embeddings 与 documents 等长有序）。

        Returns:
            本次新增记录数（按 chunk_id 幂等去重）。
        """
        if len(documents) != len(embeddings):
            raise VectorStoreError(
                f"documents({len(documents)}) 与 embeddings({len(embeddings)}) 数量不一致"
            )
        if not documents:
            return 0

        ids: List[str] = []
        docs: List[str] = []
        metas: List[Dict[str, Any]] = []
        vecs: List[List[float]] = []
        for doc, vec in zip(documents, embeddings):
            chunk_id = str(doc.metadata.get("chunk_id") or "")
            if not chunk_id:
                raise VectorStoreError("Document 缺少 chunk_id，无法入库")
            ids.append(chunk_id)
            docs.append(doc.page_content)
            # 列表字段（如 cwe_id/cve_id）序列化为 "; " 分隔字符串，
            # 使 ChromaDB 的 $contains 过滤可用（$in 对数组值无效）
            metas.append(_serialize_metadata(doc.metadata))
            vecs.append(list(vec))

        # ChromaDB 要求 id 唯一，重复 id 直接覆盖更新；
        # 单次 upsert 有 batch 大小上限（0.5.x 默认约 166），动态获取并分批写入
        try:
            batch_size = int(self._client.get_max_batch_size())
        except Exception:
            batch_size = 100
        batch_size = max(1, min(batch_size, 500))
        for start in range(0, len(ids), batch_size):
            self._collection.upsert(
                ids=ids[start : start + batch_size],
                documents=docs[start : start + batch_size],
                metadatas=metas[start : start + batch_size],
                embeddings=vecs[start : start + batch_size],
            )
        logger.info("向量库入库完成: +%d 条（collection 现有 %d 条）", len(ids), self.count())
        return len(ids)

    # ---------- 检索 ----------
    def query(
        self,
        query_embedding: Sequence[float],
        top_k: int = 5,
        where: Optional[Dict[str, Any]] = None,
        where_document: Optional[Dict[str, Any]] = None,
    ) -> List[RetrievedChunk]:
        """向量相似度检索。

        Args:
            query_embedding: 查询向量。
            top_k: 返回条数。
            where: metadata 过滤条件，如 {"cwe_id": {"$in": ["CWE-89"]}}
                   或 {"category": "owasp_cwe"}。
            where_document: 文档内容过滤（$contains 等）。

        Returns:
            按相似度降序（score 越大越相似）的 RetrievedChunk 列表。
        """
        if top_k <= 0:
            return []
        try:
            result = self._collection.query(
                query_embeddings=[list(query_embedding)],
                n_results=top_k,
                where=where or None,
                where_document=where_document or None,
                include=["documents", "metadatas", "distances"],
            )
        except Exception as exc:
            raise VectorStoreError(f"向量检索失败: {exc}") from exc

        chunks: List[RetrievedChunk] = []
        ids = result.get("ids", [[]])[0]
        docs = result.get("documents", [[]])[0]
        metas = result.get("metadatas", [[]])[0]
        distances = result.get("distances", [[]])[0]
        for idx in range(len(ids)):
            distance = float(distances[idx]) if idx < len(distances) else 0.0
            # cosine 距离 -> 相似度分数（cosine space 下 distance=1-cos_sim）
            score = 1.0 - distance
            chunks.append(
                RetrievedChunk(
                    page_content=str(docs[idx] if idx < len(docs) else ""),
                    metadata=dict(metas[idx]) if idx < len(metas) and metas[idx] else {},
                    score=round(score, 4),
                    distance=round(distance, 4),
                )
            )
        logger.debug("向量检索: top_k=%d -> %d 条", top_k, len(chunks))
        return chunks

    def get_by_document_contains(
        self,
        keyword: str,
        limit: int = 20,
        where: Optional[Dict[str, Any]] = None,
    ) -> List[RetrievedChunk]:
        """按正文包含关键词检索（不依赖向量相似度）。

        用于关键词兜底：当向量检索被大量无关数据淹没（如 CNNVD 数据
        占绝大多数）或查询为缩写/短词时，直接按正文内容命中相关 Chunk。

        Args:
            keyword: 正文需包含的关键词（子串匹配）。
            limit: 返回条数上限。
            where: metadata 过滤（如 {"category": {"$in": ["owasp_cwe"]}}），
                用于优先检索自建知识。
        """
        if not keyword or not keyword.strip():
            return []
        try:
            result = self._collection.get(
                where_document={"$contains": keyword.strip()},
                where=where or None,
                limit=limit,
                include=["documents", "metadatas"],
            )
        except Exception as exc:
            logger.warning("关键词检索失败（%s）: %s", keyword, exc)
            return []

        ids = result.get("ids", [])
        docs = result.get("documents", [])
        metas = result.get("metadatas", [])
        chunks: List[RetrievedChunk] = []
        for i in range(len(ids)):
            chunks.append(
                RetrievedChunk(
                    page_content=str(docs[i]) if i < len(docs) else "",
                    metadata=dict(metas[i]) if i < len(metas) and metas[i] else {},
                    score=1.0,
                )
            )
        logger.debug("关键词检索: '%s' -> %d 条", keyword, len(chunks))
        return chunks

    # ---------- 管理 ----------
    def count(self) -> int:
        return int(self._collection.count())

    def get_by_keywords(
        self,
        keywords: Sequence[str],
        limit: int = 20,
        where: Optional[Dict[str, Any]] = None,
    ) -> List[RetrievedChunk]:
        """按 metadata 关键词字段（keyword_0..）快速过滤检索。

        相比 where_document $contains 的全表扫描，metadata where 过滤更快且更稳。
        旧数据（无 keyword_* 字段）时命中为空，由调用方回退到 $contains。

        Args:
            keywords: 检索关键词列表（小写规范化后匹配）。
            limit: 返回条数上限。
            where: 额外 metadata 过滤（如 {"category": {"$in": [...]}}），
                与关键词条件取交集（$and）。
        """
        if not keywords:
            return []
        normalized: List[str] = []
        for kw in keywords:
            kw = str(kw).strip().lower()
            if kw and kw not in normalized:
                normalized.append(kw)
        if not normalized:
            return []
        # 每个 keyword_* 字段用 $in 匹配全部关键词（子句数 = 字段数，而非 关键词数×字段数）
        clauses: List[Dict[str, Any]] = [
            {f"keyword_{i}": {"$in": normalized}}
            for i in range(KEYWORD_MAX_FIELDS)
        ]
        query_where: Dict[str, Any] = {"$or": clauses}
        if where:
            query_where = {"$and": [query_where, where]}
        try:
            result = self._collection.get(
                where=query_where,
                limit=limit,
                include=["documents", "metadatas"],
            )
        except Exception as exc:
            logger.warning("metadata 关键词检索失败: %s", exc)
            return []

        ids = result.get("ids", [])
        docs = result.get("documents", [])
        metas = result.get("metadatas", [])
        chunks: List[RetrievedChunk] = []
        for i in range(len(ids)):
            chunks.append(
                RetrievedChunk(
                    page_content=str(docs[i]) if i < len(docs) else "",
                    metadata=dict(metas[i]) if i < len(metas) and metas[i] else {},
                    score=1.0,
                )
            )
        logger.debug("metadata 关键词检索: %s -> %d 条", list(keywords)[:3], len(chunks))
        return chunks

    def get_by_source(self, source: str) -> List[Dict[str, Any]]:
        """按来源查询记录（用于溯源 / 删除）。"""
        result = self._collection.get(
            where={"source": source},
            include=["documents", "metadatas"],
        )
        return [
            {"id": i, "document": d, "metadata": m}
            for i, d, m in zip(
                result.get("ids", []),
                result.get("documents", []),
                result.get("metadatas", []),
            )
        ]

    def delete_by_ids(self, ids: Sequence[str]) -> int:
        """按 id 删除记录。"""
        if not ids:
            return 0
        self._collection.delete(ids=list(ids))
        logger.info("向量库删除 %d 条", len(ids))
        return len(ids)

    def reset(self) -> None:
        """清空当前集合。"""
        self._client.delete_collection(self.collection_name)
        self._collection = self._client.create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info("向量库集合 %s 已清空", self.collection_name)

    def close(self) -> None:
        """关闭客户端并刷新持久化状态。

        chromadb 0.5.x 采用异步 compaction：写入后若进程直接退出，
        HNSW 索引可能未落盘（表现为跨进程加载时 'Cannot open header file'）。
        显式停止内部系统会触发落盘，必须在入库完成后调用。
        """
        try:
            system = getattr(self._client, "_system", None)
            if system is not None and hasattr(system, "stop"):
                system.stop()
            else:
                logger.warning("向量库客户端无可用关闭机制，索引可能未完全落盘")
        except Exception as exc:
            logger.warning("向量库关闭时异常: %s", exc)
