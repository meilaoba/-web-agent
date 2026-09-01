"""RAG 知识库模块（Phase 1：数据链路）。

当前实现：文档加载 -> 文本清洗 -> 文本分割 -> Metadata。
后续阶段将在此扩展：Embedding / 向量存储 / Retriever 等。

使用示例：
    from app.rag.loader import load_documents_from_dir
    from app.rag.cleaner import TextCleaner
    from app.rag.splitter import SemanticRecursiveTextSplitter
"""

from __future__ import annotations

from . import metadata as metadata  # noqa: F401
from .cleaner import CleanConfig, TextCleaner  # noqa: F401
from .loader import (  # noqa: F401
    DocumentLoadError,
    load_documents,
    load_documents_from_dir,
)
from .schemas import Document  # noqa: F401
from .splitter import SemanticRecursiveTextSplitter, estimate_tokens  # noqa: F401

__all__ = [
    "CleanConfig",
    "Document",
    "DocumentLoadError",
    "SemanticRecursiveTextSplitter",
    "TextCleaner",
    "estimate_tokens",
    "load_documents",
    "load_documents_from_dir",
]
