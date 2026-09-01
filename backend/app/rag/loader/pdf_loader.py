"""PDF 文档加载器。

使用 pypdf 提取文本：
1. 逐页提取并合并，页面间以空行分隔。
2. 记录页数 / 加密状态到 metadata。
3. 对常见 PDF 换行（行尾连字符断词、行尾换行）做轻量规整，
   更深入的清洗交给文本清洗模块（cleaner）。
"""

from __future__ import annotations

import logging
import re
from typing import List

from ..schemas import Document
from .base import BaseDocumentLoader, DocumentLoaderRegistry, DocumentLoadError

logger = logging.getLogger(__name__)

#: 行尾连字符断词：foo-\nbar -> foobar
_HYPHEN_JOIN_RE = re.compile(r"-\n")
#: 行内多余空格（保留换行）
_SPACES_RE = re.compile(r"[ \t\u3000]{2,}")


@DocumentLoaderRegistry.register(".pdf")
class PdfLoader(BaseDocumentLoader):
    """加载 PDF 文件为单个 Document。"""

    extensions = (".pdf",)

    def __init__(self, file_path, *, page_separator: str = "\n\n", **kwargs) -> None:
        super().__init__(file_path, **kwargs)
        self.page_separator = page_separator

    def load(self) -> List[Document]:
        try:
            from pypdf import PdfReader
        except ImportError as exc:  # pragma: no cover - 依赖缺失提示
            raise DocumentLoadError(
                "未安装 pypdf，无法加载 PDF。请执行: pip install -r requirements.txt"
            ) from exc

        try:
            reader = PdfReader(str(self.file_path))
        except Exception as exc:
            raise DocumentLoadError(f"PDF 读取失败 {self.file_path}: {exc}") from exc

        if reader.is_encrypted:
            # 尝试空密码解密（常见于权限受限但无密码的 PDF）
            try:
                reader.decrypt("")
            except Exception:
                raise DocumentLoadError(
                    f"PDF 已加密且无法自动解密: {self.file_path}"
                ) from None

        pages: List[str] = []
        for page in reader.pages:
            try:
                text = page.extract_text() or ""
            except Exception as exc:  # 单页失败不阻断整体
                logger.warning("PDF %s 第 %d 页提取失败: %s", self.file_path.name, len(pages) + 1, exc)
                text = ""
            text = _normalize_pdf_text(text)
            if text.strip():
                pages.append(text.strip())

        content = self.page_separator.join(pages)
        metadata = self._base_metadata()
        metadata["page_count"] = len(reader.pages)
        metadata["is_encrypted"] = bool(reader.is_encrypted)

        return [Document(page_content=content, metadata=metadata)]


def _normalize_pdf_text(text: str) -> str:
    """PDF 文本轻量规整：合并断词连字符、压缩行内空格。"""
    text = _HYPHEN_JOIN_RE.sub("", text)
    text = _SPACES_RE.sub(" ", text)
    return text
