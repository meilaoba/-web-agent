"""TXT 纯文本加载器。"""

from __future__ import annotations

from typing import List

from ..schemas import Document
from .base import BaseDocumentLoader, DocumentLoaderRegistry


@DocumentLoaderRegistry.register(".txt")
class TextLoader(BaseDocumentLoader):
    """加载 .txt 纯文本文件为单个 Document。"""

    extensions = (".txt",)

    def load(self) -> List[Document]:
        content = self._read_text()
        metadata = self._base_metadata()
        return [Document(page_content=content, metadata=metadata)]
