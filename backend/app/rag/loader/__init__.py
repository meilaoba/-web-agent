"""RAG 文档加载模块。

统一入口：
    from app.rag.loader import load_documents, load_documents_from_dir
"""

from __future__ import annotations

# 导入各格式 Loader 以完成注册（注册表自动发现）
from . import (  # noqa: F401
    cnnvd_loader,
    html_loader,
    json_loader,
    markdown_loader,
    pdf_loader,
    text_loader,
)
from .base import (  # noqa: F401
    BaseDocumentLoader,
    DocumentLoadError,
    DocumentLoaderRegistry,
    load_documents,
    load_documents_from_dir,
)

__all__ = [
    "BaseDocumentLoader",
    "DocumentLoadError",
    "DocumentLoaderRegistry",
    "load_documents",
    "load_documents_from_dir",
]
