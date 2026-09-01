"""CNNVD（国家信息安全漏洞库）XML 数据加载器。

支持 CNNVD 官方导出的漏洞数据格式（.xml 与 .xml.gz）：

    <cnnvd publisher="中国漏洞库" date="..." format="标准版">
      <cnnvd_items>
        <cnnvd_id>CNNVD-200511-081</cnnvd_id>
        <cve_id>CVE-2005-3444</cve_id>
        <name>漏洞名称</name>
        <aliases><alias>...</alias></aliases>
        <vendor>厂商</vendor>
        <product>产品</product>
        <vuln_descript>漏洞描述</vuln_descript>
        <vuln_type>漏洞类型</vuln_type>
        <severity><overallseverity>高危</overallseverity>...</severity>
        <published>2005-07-20</published>
        <modified>2005-11-03</modified>
        <references><reference><url>...</url></reference></references>
        <patch_url>...</patch_url>
      </cnnvd_items>
      ...
    </cnnvd>

设计要点：
- 使用 iterparse 流式解析，逐条产出 Document，适配大文件（数万条漏洞）；
- 每条 cnnvd_items 生成一个 Document，结构化组织 page_content，
  保留 cnnvd_id/cve_id/vendor/product/vuln_type/severity/published 到 metadata，
  便于后续向量检索过滤与知识溯源；
- 中文危险等级（高危/中危/低危/危急）映射为标准等级（High/Medium/Low/Critical）。
"""

from __future__ import annotations

import gzip
import logging
from typing import Any, Dict, Iterator, List, Optional
from xml.etree import ElementTree as ET

from ..schemas import Document
from .base import BaseDocumentLoader, DocumentLoaderRegistry, DocumentLoadError

logger = logging.getLogger(__name__)

#: 中文危险等级 -> 标准等级
_SEVERITY_MAP = {
    "危急": "Critical",
    "超危": "Critical",
    "高危": "High",
    "高": "High",
    "中危": "Medium",
    "中": "Medium",
    "低危": "Low",
    "低": "Low",
    "未知": "Info",
    "无": "Info",
}


@DocumentLoaderRegistry.register(".xml", ".xml.gz")
class CnnvdXmlLoader(BaseDocumentLoader):
    """CNNVD 漏洞数据加载器（xml / xml.gz）。"""

    extensions = (".xml", ".xml.gz")

    def load(self) -> List[Document]:
        docs: List[Document] = []
        for index, item in enumerate(self._iter_items()):
            doc = self._to_document(item, index)
            if doc.page_content.strip():
                docs.append(doc)
        logger.info("CNNVD 加载完成: %s -> %d 条漏洞", self.file_path.name, len(docs))
        return docs

    # ---------- 流式解析 ----------
    def _open(self):
        """按压缩类型打开文件（UTF-8）。"""
        if self.file_path.name.lower().endswith(".xml.gz") or self.file_path.suffix.lower() == ".gz":
            return gzip.open(self.file_path, "rt", encoding="utf-8")
        return open(self.file_path, "r", encoding="utf-8")

    def _iter_items(self) -> Iterator[ET.Element]:
        """流式产出 cnnvd_items 元素（iterparse，处理完即释放）。"""
        try:
            with self._open() as fh:
                context = ET.iterparse(fh, events=("end",))
                for _event, elem in context:
                    if elem.tag == "cnnvd_items":
                        yield elem
                        # 释放已处理元素，控制内存
                        elem.clear()
        except ET.ParseError as exc:
            raise DocumentLoadError(f"XML 解析失败 {self.file_path}: {exc}") from exc

    # ---------- 字段提取 ----------
    @staticmethod
    def _text(elem: ET.Element, path: str) -> str:
        """按 'parent/child' 路径取子元素文本，缺失返回空串。"""
        node = elem.find(path)
        return (node.text or "").strip() if node is not None and node.text else ""

    @staticmethod
    def _texts(elem: ET.Element, path: str) -> List[str]:
        """按路径取多个子元素文本列表。"""
        return [n.text.strip() for n in elem.findall(path) if n.text and n.text.strip()]

    # ---------- Document 构造 ----------
    def _to_document(self, item: ET.Element, index: int) -> Document:
        cnnvd_id = self._text(item, "cnnvd_id")
        cve_id = self._text(item, "cve_id")
        name = self._text(item, "name")
        vendor = self._text(item, "vendor")
        product = self._text(item, "product")
        descript = self._text(item, "vuln_descript")
        vuln_type = self._text(item, "vuln_type")
        published = self._text(item, "published")
        modified = self._text(item, "modified")
        overall = self._text(item, "severity/overallseverity")
        technical = self._text(item, "severity/technicalseverity")
        aliases = self._texts(item, "aliases/alias")
        refs = self._texts(item, "references/reference/url")
        patch_url = self._text(item, "patch_url")

        # 结构化正文（利于检索与语义完整）
        lines: List[str] = []
        if name:
            lines.append(name)
        lines.append("")
        if cnnvd_id:
            lines.append(f"CNNVD编号: {cnnvd_id}")
        if cve_id:
            lines.append(f"CVE编号: {cve_id}")
        if vuln_type:
            lines.append(f"漏洞类型: {vuln_type}")
        if overall or technical:
            lines.append(f"危险等级: {overall or technical}")
        if vendor:
            lines.append(f"厂商: {vendor}")
        if product:
            lines.append(f"产品: {product}")
        if published:
            lines.append(f"发布日期: {published}")
        if aliases:
            lines.append(f"别名: {'; '.join(aliases)}")
        if descript:
            lines.append("")
            lines.append(f"漏洞描述: {descript}")
        if refs:
            lines.append("")
            lines.append("参考链接:")
            lines.extend(refs)
        if patch_url:
            lines.append(f"补丁链接: {patch_url}")

        metadata: Dict[str, Any] = {
            "source": str(self.file_path.resolve()),
            "document_name": self.file_path.name,
            "file_type": self._file_type(),
            "category": "cnnvd",
            "cnnvd_id": cnnvd_id,
            "cve_id": cve_id,
            "vulnerability_type": vuln_type,
            "severity": self._map_severity(overall or technical),
            "vendor": vendor,
            "product": product,
            "published": published,
            "modified": modified,
        }
        if name:
            metadata["title"] = name

        return Document(page_content="\n".join(lines), metadata=metadata)

    def _file_type(self) -> str:
        name = self.file_path.name.lower()
        if name.endswith(".xml.gz"):
            return "xml.gz"
        if name.endswith(".xml"):
            return "xml"
        return self.file_path.suffix.lower().lstrip(".")

    @staticmethod
    def _map_severity(value: str) -> str:
        """中文危险等级映射为标准等级，未知回退 Info。"""
        if not value:
            return "Info"
        for cn, std in _SEVERITY_MAP.items():
            if cn in value:
                return std
        return value if value in ("Critical", "High", "Medium", "Low", "Info") else "Info"
