"""RAG 统一数据结构定义。

所有加载器、清洗器、分割器统一使用本模块的 Document 结构，
便于后续直接接入 Embedding / ChromaDB / Retriever。

结构（与毕设路线文档一致）：
    Document
    ├── page_content : 实际文本内容
    └── metadata     : 来源 / 文件名 / 类型 / 分类 / 漏洞类型等
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class Document:
    """RAG 统一文档对象。

    Attributes:
        page_content: 文档正文文本。
        metadata: 元数据字典。Phase 1 至少包含
            source / document_name / file_type / category，
            根据数据情况扩展 cwe_id / owasp_id / vulnerability_type 等。
    """

    page_content: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典，便于 JSON 落盘 / 后续入库。"""
        return {
            "page_content": self.page_content,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Document":
        """从字典反序列化。"""
        return cls(
            page_content=str(data.get("page_content", "")),
            metadata=dict(data.get("metadata", {})),
        )

    def __repr__(self) -> str:  # pragma: no cover - 调试辅助
        return (
            f"Document(page_content_len={len(self.page_content)}, "
            f"metadata={self.metadata})"
        )
