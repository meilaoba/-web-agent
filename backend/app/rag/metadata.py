"""Metadata 处理模块。

职责：
1. 从内容中提取知识引用（CWE / CVE / OWASP 编号），写入 metadata；
2. 规范化 metadata 值类型，确保可直接写入 ChromaDB
   （ChromaDB 要求值类型为 str / int / float / bool，None 需要剔除）；
3. 为后续检索过滤与知识溯源提供统一入口。

Phase 1 定位：本模块只做基础提取与规范化，不实现 Embedding / 检索。
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict

from .schemas import Document

logger = logging.getLogger(__name__)

#: CWE 编号，如 CWE-89 / cwe-89
_CWE_RE = re.compile(r"CWE[-_ ]?(\d{1,4})", re.IGNORECASE)
#: CVE 编号，如 CVE-2024-12345
_CVE_RE = re.compile(r"CVE[-_ ]?(\d{4}[-_ ]?\d{4,7})", re.IGNORECASE)
#: OWASP 引用，如 OWASP A03:2021 / A03:2021-Injection / OWASP Top 10
_OWASP_RE = re.compile(r"(?:OWASP\s*)?(A\d{2}:\d{4}(?:[-_][A-Za-z0-9 ]+)?)", re.IGNORECASE)

#: ChromaDB 支持的值类型
_SUPPORTED_VALUE_TYPES = (str, int, float, bool)


def extract_knowledge_metadata(text: str) -> Dict[str, Any]:
    """从文本中提取 CWE / CVE / OWASP 引用。

    Returns:
        {"cwe_id": [...], "cve_id": [...], "owasp_id": [...]}（无匹配则缺省）。
    """
    out: Dict[str, Any] = {}

    cwes = sorted({f"CWE-{int(m)}" for m in _CWE_RE.findall(text)})
    if cwes:
        out["cwe_id"] = cwes

    cves = sorted(
        {
            f"CVE-{m.replace('_', '-').replace(' ', '-').upper()}"
            for m in _CVE_RE.findall(text)
        }
    )
    if cves:
        out["cve_id"] = cves

    owasp = sorted(
        {
            m.upper().replace("_", "-")
            for m in _OWASP_RE.findall(text)
        }
    )
    if owasp:
        out["owasp_id"] = owasp

    return out


def normalize_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """规范化 metadata，使其可直接写入 ChromaDB。

    规则：
    - 仅保留 ChromaDB 支持的值类型（str / int / float / bool）；
    - 字符串值去除首尾空白；None 与空字符串剔除；
    - 字典 / 列表等复杂值降级为字符串表示（保证不丢失信息）；
    - 返回新的字典，不修改入参。
    """
    normalized: Dict[str, Any] = {}
    for key, value in metadata.items():
        if value is None:
            continue
        if isinstance(value, bool):
            normalized[key] = value
        elif isinstance(value, (int, float)):
            normalized[key] = value
        elif isinstance(value, str):
            cleaned = value.strip()
            if cleaned:
                normalized[key] = cleaned
        elif isinstance(value, (list, tuple)):
            items = [str(v).strip() for v in value if v is not None and str(v).strip()]
            if items:
                normalized[key] = items
        else:
            # 字典等复杂对象降级为 JSON 字符串
            try:
                import json

                normalized[key] = json.dumps(value, ensure_ascii=False)
            except (TypeError, ValueError):
                normalized[key] = str(value)
    return normalized


def enrich_document_metadata(doc: Document) -> Document:
    """从 Document 正文提取知识引用并合并到 metadata（不覆盖已有值）。

    用于加载器未提取到编号、但正文中实际存在引用的情况。
    """
    if not doc.metadata.get("cwe_id") or not doc.metadata.get("cve_id") or not doc.metadata.get("owasp_id"):
        extracted = extract_knowledge_metadata(doc.page_content)
        merged = dict(doc.metadata)
        for key, value in extracted.items():
            if key not in merged:
                merged[key] = value
        return Document(page_content=doc.page_content, metadata=merged)
    return doc


def enrich_documents_metadata(docs: list[Document]) -> list[Document]:
    """批量增强 metadata。"""
    return [enrich_document_metadata(d) for d in docs]
