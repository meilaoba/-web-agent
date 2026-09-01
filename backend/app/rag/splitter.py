"""文本分割模块（Chunk 切片）。

设计目标：不是机械按字符数切割，而是尽量保证语义结构完整 ——
标题、漏洞描述、漏洞成因、检测方法、修复方法、代码示例尽量落在同一 Chunk 内。

实现思路（借鉴 Recursive Character Text Splitter 的成熟算法并针对安全知识增强）：
1. **标题感知**：优先按 Markdown 标题层级切分，形成语义 Section；
2. **代码块保护**：切分前将围栏代码块替换为占位符，任何级别切分都不会
   从代码块中间切开；合并完成后若某 Chunk 仍远超目标大小（超长代码块），
   再按代码行二次切分，保证单行不被截断；
3. **递归降级**：标题 -> 空行 -> 换行 -> 中英文句子 -> 逗号 -> 空格 -> 字符；
4. **Token 估算**：chunk_size / chunk_overlap 以近似 token 数为单位
   （CJK 每字符约 1 token，其余按 4 字符约 1 token），默认 800 / 100。
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple

from .schemas import Document

logger = logging.getLogger(__name__)

#: 占位符（与 cleaner 一致，控制字符在清洗阶段已被移除，不会冲突）
_CODE_PLACEHOLDER = "\x00__CODE_BLOCK_{index}__\x00"

#: 中日韩统一表意文字（含扩展 A 与兼容区）
_CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]")

#: Markdown 标题（1~4 级）
_HEADING_RE = re.compile(r"^(#{1,4})\s+(.+?)\s*$", re.MULTILINE)

#: 围栏代码块
_FENCE_RE = re.compile(r"^(```+|~~~+)\s*([\w+#.-]*)\s*$", re.MULTILINE)

#: 递归降级分隔符（优先在更靠前的分隔符处切分）
_DEFAULT_SEPARATORS: Tuple[str, ...] = (
    "\n\n",       # 空行（段落 / 列表边界）
    "\n",         # 换行
    "。", "！", "？", "；",   # 中文句末
    ". ", "! ", "? ", "; ",  # 英文句末
    "，", ", ",   # 逗号
    " ",          # 空格
    "",           # 字符级兜底
)

#: 标题级别 -> 语义 Section 名称映射（用于 metadata.section 归一化）
_SECTION_ALIASES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("description", ("描述", "概述", "简介", "简介", "description", "summary")),
    ("cause", ("成因", "原因", "为什么", "cause", "root cause", "background")),
    ("impact", ("影响", "危害", "后果", "impact", "consequence")),
    ("detection", ("检测", "识别", "发现", "detection", "detect", "identification")),
    ("mitigation", ("修复", "防护", "防御", "缓解", "mitigation", "remediation", "fix", "prevention")),
    ("example", ("示例", "例子", "example", "sample", "演示", "漏洞代码", "安全代码", "vulnerable", "secure code")),
    ("reference", ("参考", "引用", "reference", "link")),
)


def estimate_tokens(text: str) -> int:
    """近似估算 token 数：CJK 每字符约 1 token，其余按 4 字符约 1 token。

    Args:
        text: 待估算文本。

    Returns:
        近似 token 数（至少为 1）。
    """
    if not text:
        return 0
    cjk_count = len(_CJK_RE.findall(text))
    other_count = len(text) - cjk_count
    return cjk_count + max(1, math.ceil(other_count / 4))


Tokenizer = Callable[[str], int]


@dataclass
class Chunk:
    """切分结果片段（内部结构，最终转换为 Document）。"""

    text: str
    section: Optional[str] = None


class SemanticRecursiveTextSplitter:
    """语义感知的递归文本分割器。"""

    def __init__(
        self,
        chunk_size: int = 800,
        chunk_overlap: int = 100,
        separators: Optional[Sequence[str]] = None,
        tokenizer: Optional[Tokenizer] = None,
        min_chunk_size: int = 50,
    ) -> None:
        """初始化。

        Args:
            chunk_size: 目标 Chunk 大小（近似 token 数）。
            chunk_overlap: 相邻 Chunk 重叠（近似 token 数）。
            separators: 递归降级分隔符（默认中英文混合分隔符）。
            tokenizer: token 估算函数，默认 estimate_tokens。
            min_chunk_size: 低于该大小不再继续切分（避免产生碎片）。
        """
        if chunk_overlap >= chunk_size:
            raise ValueError(f"chunk_overlap({chunk_overlap}) 必须小于 chunk_size({chunk_size})")
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.separators = list(separators) if separators else list(_DEFAULT_SEPARATORS)
        self.tokenizer = tokenizer or estimate_tokens
        self.min_chunk_size = min_chunk_size

    # ---------- 对外接口 ----------
    def split_documents(self, docs: Sequence[Document]) -> List[Document]:
        """批量分割 Document 列表。"""
        chunks: List[Document] = []
        for doc in docs:
            chunks.extend(self.split_document(doc))
        return chunks

    def split_document(self, doc: Document) -> List[Document]:
        """将单个 Document 分割为带扩展 metadata 的 Chunk 列表。"""
        source_id = self._source_id(doc)
        # 文档级内容哈希：处理"单文件多 Document"（如 CNNVD 一文件拆成千条漏洞），
        # 保证 chunk_id 全局唯一且稳定（不依赖文档处理顺序）
        doc_hash = hashlib.md5(doc.page_content.encode("utf-8")).hexdigest()[:8]
        chunks = self.split_text(doc.page_content)
        result: List[Document] = []
        for index, chunk in enumerate(chunks):
            metadata = dict(doc.metadata)
            metadata.update(
                {
                    "chunk_index": index,
                    "chunk_id": f"{source_id}-{doc_hash}-{index:04d}",
                    "token_count": self.tokenizer(chunk.text),
                }
            )
            if chunk.section:
                metadata["section"] = chunk.section
            result.append(Document(page_content=chunk.text, metadata=metadata))
        return result

    def split_text(self, text: str) -> List[Chunk]:
        """分割纯文本为 Chunk 列表。"""
        if not text.strip():
            return []

        protected, code_blocks = self._protect_code_blocks(text)

        # 1. 标题感知 + 递归降级切分（在保护文本上进行，保证切分点不落在代码块内）
        segments = self._split_semantic(protected)

        # 2. 恢复代码块后再合并：token 估算基于真实文本，避免占位符导致失真
        restored_segments = [
            self._restore_code_blocks(s, code_blocks) for s in segments
        ]

        # 3. 贪心合并片段到目标大小，相邻 Chunk 保留重叠
        merged = self._merge_with_overlap(restored_segments)

        # 4. 对合并后仍超长的 Chunk（通常为超长代码块），按行二次切分
        threshold = int(self.chunk_size * 1.2)
        final: List[Chunk] = []
        for text_chunk in merged:
            if self.tokenizer(text_chunk) > threshold:
                final.extend(self._split_oversized(text_chunk))
            else:
                final.append(Chunk(text=text_chunk, section=self._infer_section(text_chunk)))

        logger.info(
            "文本分割完成: %d 字符 -> %d Chunk（size=%d, overlap=%d）",
            len(text),
            len(final),
            self.chunk_size,
            self.chunk_overlap,
        )
        return final

    # ---------- 核心切分逻辑 ----------
    def _split_semantic(self, text: str) -> List[str]:
        """标题感知的递归切分，返回语义尽量完整的片段列表。"""
        # 优先按标题层级切分
        heading_split = self._split_by_headings(text)
        if heading_split is not None:
            return self._flatten(heading_split)

        # 无标题结构时按分隔符递归降级
        return self._recursive_split(text, self.separators, 0)

    def _split_by_headings(self, text: str) -> Optional[List[str]]:
        """按 Markdown 标题切分。

        规则：所有标题（1~4 级）都作为切分点，每个标题与其后续内容组成
        一个语义 Section；第一个标题之前的内容作为"引言"Section。
        未发现标题时返回 None（交给分隔符递归）。
        """
        matches = list(_HEADING_RE.finditer(text))
        if not matches:
            return None

        sections: List[str] = []
        prev_end = 0
        for m in matches:
            pre = text[prev_end : m.start()].strip()
            if pre:
                sections.append(pre)
            prev_end = m.start()
        tail = text[prev_end:].strip()
        if tail:
            sections.append(tail)
        return sections

    def _recursive_split(self, text: str, separators: List[str], depth: int) -> List[str]:
        """按分隔符递归降级切分（核心递归）。"""
        if self.tokenizer(text) <= self.chunk_size or not separators or depth > 6:
            return [text] if text.strip() else []

        separator = separators[0]
        remaining = separators[1:]

        if separator == "":
            # 字符级兜底：按字符硬切（每 chunk_size 个字符，保留 overlap）
            return self._split_by_char(text)

        parts = text.split(separator)
        # 忽略空片段，但保留分隔符语义（追加回片段）
        non_empty: List[str] = []
        for part in parts:
            piece = part.strip()
            if piece:
                non_empty.append(piece)

        out: List[str] = []
        for piece in non_empty:
            if self.tokenizer(piece) <= self.chunk_size:
                out.append(piece)
            else:
                out.extend(self._recursive_split(piece, remaining, depth + 1))
        return out

    def _split_by_char(self, text: str) -> List[str]:
        """字符级硬切（兜底），相邻片段保留 overlap。"""
        if self.tokenizer(text) <= self.chunk_size:
            return [text] if text.strip() else []

        size = max(1, self.chunk_size)
        overlap = min(self.chunk_overlap, size // 2)
        chunks: List[str] = []
        start = 0
        while start < len(text):
            end = min(start + size, len(text))
            chunk = text[start:end]
            if chunk.strip():
                chunks.append(chunk)
            if end >= len(text):
                break
            start = max(start, end - overlap)
        return chunks

    def _merge_with_overlap(self, segments: List[str]) -> List[str]:
        """贪心合并片段到 chunk_size，相邻 Chunk 保留 overlap 尾部文本。

        单片段超长（token > chunk_size）时作为独立 Chunk 落盘，不并入其他片段，
        避免一个超长段拖拽后续内容形成更大 Chunk。
        """
        if not segments:
            return []

        merged: List[str] = []
        current: List[str] = []
        current_tokens = 0

        def join(parts: List[str]) -> str:
            return "\n\n".join(parts)

        for seg in segments:
            seg_tokens = self.tokenizer(seg)
            if seg_tokens > self.chunk_size:
                # 超长单段：先落盘当前，再单独落盘该段（超长段由后续 _split_oversized 处理）
                if current:
                    merged.append(join(current))
                    current = []
                    current_tokens = 0
                merged.append(seg)
                continue
            if current and current_tokens + seg_tokens > self.chunk_size:
                # 当前 Chunk 已满，落盘
                merged.append(join(current))
                # 保留尾部片段作为下一个 Chunk 的开头（overlap）
                while current and current_tokens > self.chunk_overlap:
                    current_tokens -= self.tokenizer(current[0])
                    current.pop(0)
                if not current:
                    current.append(seg)
                    current_tokens = seg_tokens
                    continue
            current.append(seg)
            current_tokens += seg_tokens

        if current:
            merged.append(join(current))
        return merged

    # ---------- 超长 Chunk 二次切分 ----------
    def _split_oversized(self, text: str) -> List[Chunk]:
        """对恢复后仍超长的 Chunk（通常含超长代码块）按行二次切分。

        切分点只落在行之间，保证单行（含单行 Payload / 语句）不被截断。
        """
        lines = text.split("\n")
        chunks: List[Chunk] = []
        current: List[str] = []
        current_tokens = 0

        for line in lines:
            line_tokens = self.tokenizer(line)
            if current and current_tokens + line_tokens > self.chunk_size:
                chunk_text = "\n".join(current)
                chunks.append(Chunk(text=chunk_text, section=self._infer_section(chunk_text)))
                # 保留尾部行作为 overlap
                while current and current_tokens > self.chunk_overlap:
                    current_tokens -= self.tokenizer(current[0])
                    current.pop(0)
            current.append(line)
            current_tokens += line_tokens

        if current:
            chunk_text = "\n".join(current)
            chunks.append(Chunk(text=chunk_text, section=self._infer_section(chunk_text)))
        return chunks

    # ---------- 辅助 ----------
    def _protect_code_blocks(self, text: str) -> Tuple[str, List[str]]:
        """提取围栏代码块并替换为占位符。"""
        blocks: List[str] = []
        parts: List[str] = []
        cursor = 0
        block_index = 0
        i = 0
        n = len(text)
        while i < n:
            opening = _FENCE_RE.match(text, i)
            if opening is None:
                i += 1
                continue
            fence = opening.group(1)
            closing = self._find_closing_fence(text, opening.end(), fence)
            if closing is None:
                i = opening.end()
                continue
            parts.append(text[cursor:opening.start()])
            blocks.append(text[opening.start() : closing.end()])
            parts.append(_CODE_PLACEHOLDER.format(index=block_index))
            block_index += 1
            cursor = closing.end()
            i = closing.end()
        parts.append(text[cursor:])
        return "".join(parts), blocks

    @staticmethod
    def _find_closing_fence(text: str, start: int, fence: str):
        """查找闭合围栏（同字符，长度 >= 开头围栏）。"""
        pos = start
        while pos < len(text):
            m = _FENCE_RE.match(text, pos)
            if m is not None and m.group(1) == fence and len(m.group(1)) >= len(fence):
                return m
            pos += 1
        return None

    def _restore_code_blocks(self, text: str, blocks: List[str]) -> str:
        for index, raw in enumerate(blocks):
            text = text.replace(_CODE_PLACEHOLDER.format(index=index), raw)
        return text

    def _infer_section(self, text: str) -> Optional[str]:
        """从 Chunk 文本推断所属语义 Section（归一化名称）。

        从后向前匹配标题：Chunk 尾部的标题更贴近 Chunk 主体内容。
        命中别名表返回规范化名称（如 example），否则返回原始标题文本。
        """
        headings = list(_HEADING_RE.finditer(text))
        if not headings:
            return None
        for m in reversed(headings):
            heading = m.group(2).strip().lower()
            for canonical, aliases in _SECTION_ALIASES:
                if any(alias in heading for alias in aliases):
                    return canonical
        return headings[-1].group(2).strip()

    @staticmethod
    def _source_id(doc: Document) -> str:
        """生成稳定的 Chunk id 前缀（基于来源路径哈希 + 文档名）。"""
        source = str(doc.metadata.get("source", ""))
        name = str(doc.metadata.get("document_name", "doc"))
        digest = hashlib.md5(source.encode("utf-8")).hexdigest()[:8]
        stem = re.sub(r"[^\w\-]+", "_", name)[:40] or "doc"
        return f"{stem}-{digest}"

    def _flatten(self, sections: List[str]) -> List[str]:
        """将 Section 列表展开：超长 Section 继续递归切分，其余保留。"""
        out: List[str] = []
        for section in sections:
            if self.tokenizer(section) <= self.chunk_size:
                out.append(section)
            else:
                out.extend(self._recursive_split(section, self.separators, 0))
        return out
