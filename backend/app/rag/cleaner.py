"""文本清洗模块。

目标：删除噪声，保留安全知识语义。

本模块面向 Web 安全知识库设计，核心约束：
- 代码示例、Payload、漏洞描述、检测 / 修复方法、CWE / OWASP 编号等
  属于重要知识，**禁止**在清洗阶段被删除或破坏。
- 实现方式：先"保护" Markdown 围栏代码块（``` ... ```），对代码块外部
  执行清洗，最后恢复代码块原文。

可配置的清洗步骤（CleanConfig）：
1. 控制字符 / 零宽字符清理
2. HTML 标签剥离（默认关闭 —— 因为 `<script>alert(1)</script>` 这类内容
   既是标签也是 Payload，误删会破坏安全知识）
3. 噪声行删除（导航 / 版权 / 弹窗提示等，模式可配置）
4. 连续重复行去重
5. 空白规范化（尾部空白、连续空行、行内多空格，保留行首缩进）
"""

from __future__ import annotations
import logging
import re
from dataclasses import dataclass
from typing import List, Sequence, Tuple
from .schemas import Document

logger = logging.getLogger(__name__)

#: Markdown 围栏代码块开头（支持 ```lang 与 ~~~lang 及无语言标注）
_FENCE_RE = re.compile(r"^(```+|~~~+)\s*([\w+#.-]*)\s*$", re.MULTILINE)

#: 零宽 / 不可见字符
_ZERO_WIDTH_RE = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064]"
)
#: BOM
_BOM_RE = re.compile(r"^\ufeff")

#: 控制字符（保留 \n \t \r）
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

#: 行内连续空白（前后均为非空白字符时压缩，保留行首缩进）
_INLINE_SPACES_RE = re.compile(r"(?<=\S)[ \t\u3000]{2,}(?=\S)")

#: 代码块占位符（\x00 已被控制字符清理删除，不会与正文冲突）
_CODE_PLACEHOLDER = "\x00__CODE_BLOCK_{index}__\x00"


@dataclass
class CleanConfig:
    """清洗配置。"""

    #: 判为噪声行的正则（整行匹配），默认取全局配置 settings.noise_line_patterns
    noise_line_patterns: Tuple[str, ...] = ()
    #: 是否删除连续重复行
    remove_duplicate_lines: bool = True
    #: 最多保留的连续空行数
    max_blank_lines: int = 1
    #: 是否剥离 HTML 标签（默认 False，防止误删 Payload）
    strip_html_tags: bool = False


class TextCleaner:
    """安全知识文本清洗器。"""

    def __init__(self, config: CleanConfig | None = None) -> None:
        self.config = config or CleanConfig()
        if not self.config.noise_line_patterns:
            # 延迟导入避免与 config 循环依赖
            from ..config import settings

            self.config.noise_line_patterns = settings.noise_line_patterns
        self._noise_res: List[re.Pattern[str]] = [
            re.compile(p, re.IGNORECASE) for p in self.config.noise_line_patterns
        ]

    # ---------- 对外接口 ----------
    def clean(self, text: str) -> str:
        """清洗单段文本。"""
        if not text:
            return text
        if not text.strip():
            return ""

        text = self._remove_control_chars(text)
        protected, blocks = self._protect_code_blocks(text)

        if self.config.strip_html_tags:
            protected = self._strip_html_tags(protected)

        protected = self._remove_noise_lines(protected)
        if self.config.remove_duplicate_lines:
            protected = self._remove_duplicate_lines(protected)
        protected = self._normalize_whitespace(protected)

        return self._restore_code_blocks(protected, blocks)

    def clean_document(self, doc: Document) -> Document:
        """清洗单个 Document，保留并校验 metadata。"""
        cleaned = self.clean(doc.page_content)
        logger.debug(
            "清洗完成: %s (%d -> %d 字符)",
            doc.metadata.get("document_name"),
            len(doc.page_content),
            len(cleaned),
        )
        return Document(page_content=cleaned, metadata=dict(doc.metadata))

    def clean_documents(self, docs: Sequence[Document]) -> List[Document]:
        """批量清洗。"""
        return [self.clean_document(d) for d in docs]

    # ---------- 内部步骤 ----------
    def _remove_control_chars(self, text: str) -> str:
        text = _BOM_RE.sub("", text)
        text = _ZERO_WIDTH_RE.sub("", text)
        return _CONTROL_RE.sub("", text)

    def _protect_code_blocks(self, text: str) -> Tuple[str, List[str]]:
        """提取围栏代码块并用占位符替换，返回 (处理文本, 代码块列表)。

        配对规则：从每个围栏开头向后查找首个同字符、长度 >= 该围栏的闭合围栏。
        """
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
                # 无配对闭合围栏：视为普通文本，跳过该位置继续扫描
                i = opening.end()
                continue
            parts.append(text[cursor:opening.start()])
            blocks.append(text[opening.start():closing.end()])
            parts.append(_CODE_PLACEHOLDER.format(index=block_index))
            block_index += 1
            cursor = closing.end()
            i = closing.end()
        parts.append(text[cursor:])
        return "".join(parts), blocks

    @staticmethod
    def _find_closing_fence(text: str, start: int, fence: str):
        """从 start 起查找与 fence 同字符且长度 >= 的闭合围栏，未找到返回 None。"""
        pos = start
        n = len(text)
        while pos < n:
            m = _FENCE_RE.match(text, pos)
            if m is not None and m.group(1) == fence and len(m.group(1)) >= len(fence):
                return m
            pos += 1
        return None

    def _strip_html_tags(self, text: str) -> str:
        """剥离 HTML 标签（保守实现，默认关闭）。"""
        # 删除成对标签整体（script / style / head），避免留下标签文本
        for tag in ("script", "style", "head"):
            text = re.sub(
                rf"<\s*{tag}\b[^>]*>.*?</\s*{tag}\s*>",
                " ",
                text,
                flags=re.IGNORECASE | re.DOTALL,
            )
        # 删除其余成对 / 自闭合标签，保留标签内文本
        text = re.sub(r"<[^>]+>", " ", text)
        return text

    def _remove_noise_lines(self, text: str) -> str:
        """删除匹配噪声模式的整行。"""
        if not self._noise_res:
            return text
        lines = text.split("\n")
        kept: List[str] = []
        removed = 0
        for line in lines:
            stripped = line.strip()
            if stripped and any(res.fullmatch(stripped) for res in self._noise_res):
                removed += 1
                continue
            kept.append(line)
        if removed:
            logger.debug("清洗: 删除 %d 行噪声内容", removed)
        return "\n".join(kept)

    def _remove_duplicate_lines(self, text: str) -> str:
        """删除连续重复的行（保留首次出现）。"""
        lines = text.split("\n")
        out: List[str] = []
        removed = 0
        for idx, line in enumerate(lines):
            if idx > 0 and line == lines[idx - 1]:
                removed += 1
                continue
            out.append(line)
        if removed:
            logger.debug("清洗: 删除 %d 行重复内容", removed)
        return "\n".join(out)

    def _normalize_whitespace(self, text: str) -> str:
        """空白规范化：尾部空白、连续空行、行内多空格（保留行首缩进）。"""
        lines = [line.rstrip() for line in text.split("\n")]
        text = "\n".join(lines)

        # 行内 2+ 空格压缩为 1（不影响代码块：此时代码块已被占位符替换；
        # 不影响行首缩进：前后必须是非空白字符）
        text = _INLINE_SPACES_RE.sub(" ", text)

        # 连续空行压缩
        blank = "\n" * (self.config.max_blank_lines + 1)
        single = "\n" * self.config.max_blank_lines
        prev = None
        while prev != text:
            prev = text
            text = text.replace(blank, single)
        return text

    def _restore_code_blocks(self, text: str, blocks: List[str]) -> str:
        """将占位符恢复为原始代码块。"""
        for index, raw in enumerate(blocks):
            text = text.replace(_CODE_PLACEHOLDER.format(index=index), raw)
        return text
