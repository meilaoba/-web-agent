"""JSON 知识数据加载器。

安全知识库中可能以 JSON 形式保存结构化数据（如 CWE 映射表、漏洞清单）。
本加载器：
1. 将 JSON 对象递归展平为可检索的纯文本（key: value 逐行），
   保证列表/嵌套对象也进入 page_content 而非丢失。
2. 从白名单键中提取元数据（cwe_id / cve_id / owasp / name / category /
   vulnerability_type / severity / language 等），供后续 ChromaDB 过滤使用。

白名单键可覆盖：通过构造参数 metadata_keys 传入。
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Sequence, Set

from ..schemas import Document
from .base import BaseDocumentLoader, DocumentLoaderRegistry, DocumentLoadError

logger = logging.getLogger(__name__)

#: 允许提升为 metadata 的顶层键（其余键仅进入正文）
_DEFAULT_METADATA_KEYS: Set[str] = {
    "cwe_id",
    "cve_id",
    "owasp_id",
    "owasp",
    "name",
    "title",
    "category",
    "vulnerability_type",
    "severity",
    "language",
    "source",
    "document_name",
}


@DocumentLoaderRegistry.register(".json")
class JsonLoader(BaseDocumentLoader):
    """加载 JSON 文件为单个 Document（对象）或多个 Document（数组）。"""

    extensions = (".json",)

    def __init__(
        self,
        file_path,
        *,
        metadata_keys: Optional[Sequence[str]] = None,
        **kwargs,
    ) -> None:
        super().__init__(file_path, **kwargs)
        self.metadata_keys: Set[str] = (
            set(metadata_keys) if metadata_keys else set(_DEFAULT_METADATA_KEYS)
        )

    def load(self) -> List[Document]:
        try:
            data = json.loads(self.file_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
            raise DocumentLoadError(f"JSON 解析失败 {self.file_path}: {exc}") from exc

        items = data if isinstance(data, list) else [data]
        docs: List[Document] = []
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                # 顶层为标量 / 字符串列表等，整体作为一个 Document
                item = {"value": item}
            metadata = self._base_metadata()
            if len(items) > 1:
                metadata["item_index"] = idx
            metadata.update(self._extract_metadata(item))
            docs.append(
                Document(page_content=_flatten(item, depth=0), metadata=metadata)
            )
        return docs

    def _extract_metadata(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """从 JSON 顶层键提取元数据（仅白名单内且值可序列化的键）。"""
        out: Dict[str, Any] = {}
        for key in self.metadata_keys:
            if key in item and item[key] is not None:
                value = item[key]
                if isinstance(value, (str, int, float, bool)):
                    out[key] = value
        return out


def _flatten(obj: Any, depth: int = 0, prefix: str = "") -> str:
    """将 JSON 对象递归展平为 'key: value' 行文本。"""
    lines: List[str] = []
    indent = "  " * min(depth, 6)

    if isinstance(obj, dict):
        for key, value in obj.items():
            label = f"{prefix}{key}" if prefix else str(key)
            if isinstance(value, (dict, list)):
                lines.append(f"{indent}{label}:")
                lines.append(_flatten(value, depth + 1))
            else:
                lines.append(f"{indent}{label}: {_stringify(value)}")
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            label = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            if isinstance(value, (dict, list)):
                lines.append(f"{indent}{label}:")
                lines.append(_flatten(value, depth + 1))
            else:
                lines.append(f"{indent}{label}: {_stringify(value)}")
    else:
        lines.append(f"{indent}{prefix}: {_stringify(obj)}")

    return "\n".join(lines)


def _stringify(value: Any) -> str:
    """将标量转为文本，None 显示为空。"""
    if value is None:
        return ""
    return str(value)
