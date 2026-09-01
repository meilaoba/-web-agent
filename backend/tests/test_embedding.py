"""Embedding 模块测试。"""

from __future__ import annotations

from app.rag.embedding import (
    EmbeddingProvider,
    HashingEmbeddingProvider,
    get_embedding_provider,
)


class TestHashingEmbedding:
    def test_dimension(self):
        provider = HashingEmbeddingProvider(dimension=64)
        assert provider.dimension == 64

    def test_deterministic(self):
        provider = HashingEmbeddingProvider(dimension=128)
        v1 = provider.embed_texts(["CWE-89 SQL 注入"])
        v2 = provider.embed_texts(["CWE-89 SQL 注入"])
        assert v1 == v2

    def test_l2_normalized(self):
        import math

        provider = HashingEmbeddingProvider(dimension=128)
        vec = provider.embed_texts(["安全知识"])[0]
        norm = math.sqrt(sum(x * x for x in vec))
        assert abs(norm - 1.0) < 1e-6

    def test_similar_texts_closer(self):
        """相似文本的向量距离应小于不相似文本。"""
        import math

        provider = HashingEmbeddingProvider(dimension=256)
        a = provider.embed_texts(["SQL 注入 参数化查询 防止"])[0]
        b = provider.embed_texts(["SQL 注入 参数化查询 修复"])[0]
        c = provider.embed_texts(["文件上传 类型校验 白名单"])[0]

        def dist(x, y):
            return 1.0 - sum(i * j for i, j in zip(x, y))

        assert dist(a, b) < dist(a, c)

    def test_interface_contract(self):
        assert issubclass(HashingEmbeddingProvider, EmbeddingProvider)
        provider = HashingEmbeddingProvider()
        assert len(provider.embed_query("测试")) == provider.dimension


class TestFactory:
    def test_hashing_factory(self):
        provider = get_embedding_provider()
        assert isinstance(provider, HashingEmbeddingProvider)  # 默认配置为 hashing
