"""Embedding 模块。

设计原则（毕设路线 规则7：组件可替换）：
- EmbeddingProvider 为抽象基类，业务代码只依赖该接口；
- 实现可替换：BGE-M3（本地模型）/ Hashing（降级，测试与演示）；
- 通过 settings.embedding_provider 配置选择，模型路径/设备均可配置，
  未来可无缝切换到 API 型 Embedding。

使用：
    from app.rag.embedding import get_embedding_provider
    provider = get_embedding_provider()
    vectors = provider.embed_texts(["CWE-89 SQL 注入", "XSS 漏洞"])
    query_vec = provider.embed_query("什么是SQL注入")
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
from abc import ABC, abstractmethod
from typing import List, Sequence

logger = logging.getLogger(__name__)


class EmbeddingProvider(ABC):
    """Embedding 提供方抽象基类。"""

    @property
    @abstractmethod
    def dimension(self) -> int:
        """向量维度。"""

    @abstractmethod
    def embed_texts(self, texts: Sequence[str]) -> List[List[float]]:
        """批量文本向量化。"""

    def embed_query(self, query: str) -> List[float]:
        """查询文本向量化（默认复用 embed_texts）。"""
        return self.embed_texts([query])[0]


class BgeM3EmbeddingProvider(EmbeddingProvider):
    """BGE-M3 本地模型实现（FlagEmbedding / sentence-transformers）。

    毕设路线推荐 BGE-M3（中英文能力好、可本地运行）。
    模型较大（约 2.2GB），首次运行需下载，可配置本地模型路径：
        EMBEDDING_MODEL=/path/to/bge-m3 或 BAAI/bge-m3
    """

    def __init__(
        self,
        model_name: str = "BAAI/bge-m3",
        device: str = "cpu",
        use_fp16: bool = False,
    ) -> None:
        self.model_name = model_name
        self.device = device
        self.use_fp16 = use_fp16
        self._model = None

    def _load(self):
        """懒加载模型。"""
        if self._model is not None:
            return self._model
        try:
            from FlagEmbedding import BGEM3FlagModel

            logger.info("加载 BGE-M3 模型: %s (device=%s)", self.model_name, self.device)
            self._model = BGEM3FlagModel(
                self.model_name,
                use_fp16=self.use_fp16,
                device=self.device,
            )
            self._use_flag = True
        except ImportError:
            try:
                from sentence_transformers import SentenceTransformer

                logger.info(
                    "FlagEmbedding 不可用，改用 sentence-transformers 加载 %s",
                    self.model_name,
                )
                self._model = SentenceTransformer(self.model_name, device=self.device)
                self._use_flag = False
            except ImportError as exc:
                raise RuntimeError(
                    "未安装 FlagEmbedding / sentence-transformers，无法加载 BGE-M3。"
                    "请执行: pip install FlagEmbedding 或 sentence-transformers"
                ) from exc
        return self._model

    @property
    def dimension(self) -> int:
        self._load()
        if self._use_flag:
            return int(self._model.sentence_embedding_dimension)
        return int(self._model.get_sentence_embedding_dimension())

    def embed_texts(self, texts: Sequence[str]) -> List[List[float]]:
        self._load()
        if not texts:
            return []
        if self._use_flag:
            out = self._model.encode(list(texts), return_dense=True, max_length=8192)
            return [vec.tolist() for vec in out["dense_vecs"]]
        vecs = self._model.encode(list(texts), normalize_embeddings=True)
        return [v.tolist() for v in vecs]


class HashingEmbeddingProvider(EmbeddingProvider):
    """确定性哈希 Embedding（降级实现）。

    用途：
    1. 无 GPU / 未下载模型的环境下验证"Embedding -> 向量库 -> 检索"整条链路；
    2. 单元测试（确定性、低维、快速）；
    3. 演示时无需下载 2.2GB 模型。

    语义区分度低于真实模型，生产环境应切换为 BGE-M3。
    原理：对文本做词袋 + 特征哈希（feature hashing）并 L2 归一化。
    """

    def __init__(self, dimension: int = 256) -> None:
        self._dimension = dimension

    @property
    def dimension(self) -> int:
        return self._dimension

    def embed_texts(self, texts: Sequence[str]) -> List[List[float]]:
        return [self._embed_one(text) for text in texts]

    def _embed_one(self, text: str) -> List[float]:
        vec = [0.0] * self._dimension
        for token in self._tokenize(text):
            digest = hashlib.md5(token.encode("utf-8")).digest()
            idx = int.from_bytes(digest[:4], "little") % self._dimension
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            vec[idx] += sign
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        """粗粒度分词：CJK 逐字 + ASCII 词（小写归一化）。"""
        tokens: List[str] = []
        # CJK 字符逐字
        for ch in text:
            if "\u4e00" <= ch <= "\u9fff" or "\u3400" <= ch <= "\u4dbf":
                tokens.append(ch)
        # ASCII 词（4 字符以上，小写归一化，消除 SSRF/ssrf 大小写差异）
        tokens.extend(re.findall(r"[A-Za-z0-9_]{3,}", text.lower()))
        return tokens


_PROVIDER_CACHE = {}


def get_embedding_provider() -> EmbeddingProvider:
    """工厂：按配置返回 Embedding 提供方（进程内缓存单例）。"""
    from ..config import settings

    key = settings.embedding_provider
    if key in _PROVIDER_CACHE:
        return _PROVIDER_CACHE[key]

    provider_name = settings.embedding_provider.lower()
    if provider_name in ("bge_m3", "bgem3", "bge-m3", "local"):
        provider: EmbeddingProvider = BgeM3EmbeddingProvider(
            model_name=settings.embedding_model,
            device=settings.embedding_device,
        )
        logger.info("Embedding 提供方: BGE-M3（%s）", settings.embedding_model)
    elif provider_name in ("hashing", "hash", "mock", ""):
        provider = HashingEmbeddingProvider(dimension=settings.embedding_dimension)
        logger.warning(
            "Embedding 提供方: Hashing（降级实现，仅用于测试/演示，生产请配置 EMBEDDING_PROVIDER=bge_m3）"
        )
    else:
        raise ValueError(f"未知 Embedding 提供方: {settings.embedding_provider}")

    _PROVIDER_CACHE[key] = provider
    return provider
