"""HTML 文档加载器。

使用 BeautifulSoup 提取正文：
1. 删除 script / style / noscript 等非正文内容。
2. 删除导航类区块（nav / header / footer / aside / form），减少网页噪声。
3. 保留正文段落、标题、代码块（pre / code）与表格的基本结构。
"""

from __future__ import annotations

import logging
from typing import List

from bs4 import BeautifulSoup, Tag

from ..schemas import Document
from .base import BaseDocumentLoader, DocumentLoaderRegistry, DocumentLoadError

logger = logging.getLogger(__name__)

#: 加载阶段即剔除的区块标签（导航 / 交互 / 元信息）
_REMOVE_TAGS: tuple[str, ...] = ("script", "style", "noscript", "iframe", "form", "svg", "canvas")

#: 视为"网页框架噪声"的区块标签
_REMOVE_BLOCK_TAGS: tuple[str, ...] = ("nav", "header", "footer", "aside")

#: 保留其文本内容但剥离自身的容器标签
_UNWRAP_TAGS: tuple[str, ...] = ("b", "strong", "i", "em", "u", "span", "a", "font", "small", "code")


@DocumentLoaderRegistry.register(".html", ".htm")
class HtmlLoader(BaseDocumentLoader):
    """加载 HTML 文件为单个 Document（正文纯文本）。"""

    extensions = (".html", ".htm")

    def load(self) -> List[Document]:
        raw = self._read_text()
        try:
            soup = BeautifulSoup(raw, "html.parser")
        except Exception as exc:  # BeautifulSoup 解析异常面较广，统一包装
            raise DocumentLoadError(f"HTML 解析失败 {self.file_path}: {exc}") from exc

        for tag in _REMOVE_TAGS:
            for node in soup.find_all(tag):
                node.decompose()
        for tag in _REMOVE_BLOCK_TAGS:
            for node in soup.find_all(tag):
                node.decompose()

        # pre / code / table 保留原始结构，其余容器标签仅保留文本
        for node in soup.find_all(True):
            if not isinstance(node, Tag):
                continue
            if node.name in _UNWRAP_TAGS:
                node.unwrap()

        metadata = self._base_metadata()
        title_node = soup.find("title")
        if title_node and title_node.get_text(strip=True):
            metadata["title"] = title_node.get_text(strip=True)

        content = _extract_text(soup)
        return [Document(page_content=content, metadata=metadata)]


def _extract_text(soup: BeautifulSoup) -> str:
    """将清理后的 HTML 树转为正文文本，保留块级结构。"""
    blocks: List[str] = []
    for element in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6", "p", "pre", "li", "tr", "br", "div"]):
        if element.name == "br":
            blocks.append("")
            continue
        text = element.get_text("\n", strip=False)
        text = _normalize_spaces(text)
        if element.name in ("h1", "h2", "h3", "h4", "h5", "h6"):
            text = "# " * int(element.name[1]) + text  # h1 -> #, h2 -> ## ...
        if text.strip():
            blocks.append(text.strip())
    return "\n".join(blocks)


def _normalize_spaces(text: str) -> str:
    """压缩行内多余空白（保留换行）。"""
    import re

    return re.sub(r"[ \t\u3000]+", " ", text)
