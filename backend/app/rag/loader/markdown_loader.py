"""Markdown 文档加载器。

除了正文，还提取一级标题（首个 `# `）与文档中的 CWE/OWASP 引用，
写入 metadata，供后续检索过滤与溯源使用。
"""

from __future__ import annotations

import re
from typing import List

from ..schemas import Document
from .base import BaseDocumentLoader, DocumentLoaderRegistry

_TITLE_RE = re.compile(r"^\s*#\s+(.+?)\s*$", re.MULTILINE)


@DocumentLoaderRegistry.register(".md", ".markdown")
class MarkdownLoader(BaseDocumentLoader):
    """加载 Markdown 文件为单个 Document。"""

    extensions = (".md", ".markdown")

    def load(self) -> List[Document]:
        content = self._read_text()
        metadata = self._base_metadata()

        title_match = _TITLE_RE.search(content)
        if title_match:
            metadata["title"] = title_match.group(1).strip()

        # 提取文档级 CWE / OWASP 引用（章节级引用由 metadata 模块按 Chunk 提取）
        cwe_ids = sorted(set(re.findall(r"CWE-\d{1,4}", content, flags=re.IGNORECASE)))
        if cwe_ids:
            metadata["cwe_id"] = cwe_ids

        return [Document(page_content=content, metadata=metadata)]
