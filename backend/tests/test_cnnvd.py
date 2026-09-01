"""CNNVD 加载器测试。"""

from __future__ import annotations

import gzip

import pytest

from app.rag.loader import DocumentLoaderRegistry, load_documents

#: 最小 CNNVD XML 样例（含缺失字段的条目，验证容错）
SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<cnnvd publisher="中国漏洞库" date="2005-12-31" format="标准版">
  <cnnvd_items>
    <cnnvd_id>CNNVD-200501-001</cnnvd_id>
    <cve_id>CVE-2005-0001</cve_id>
    <name>示例缓冲区溢出漏洞</name>
    <vendor>Example</vendor>
    <product>web server</product>
    <vuln_descript>攻击者可通过构造恶意请求触发缓冲区溢出，导致远程代码执行。</vuln_descript>
    <vuln_type>缓冲区溢出</vuln_type>
    <severity><overallseverity>高危</overallseverity></severity>
    <published>2005-01-01</published>
    <modified>2005-02-01</modified>
    <references><reference><url>http://example.com/advisory/1</url></reference></references>
    <patch_url>http://example.com/patch</patch_url>
  </cnnvd_items>
  <cnnvd_items>
    <cnnvd_id>CNNVD-200501-002</cnnvd_id>
    <name>无CVE编号的示例漏洞</name>
    <vendor>Acme</vendor>
    <vuln_descript>该条目缺少 cve_id、product、severity 等字段，验证容错。</vuln_descript>
    <vuln_type>安全漏洞</vuln_type>
    <published>2005-01-02</published>
  </cnnvd_items>
</cnnvd>
"""


@pytest.fixture()
def cnnvd_xml(tmp_path):
    p = tmp_path / "cnnvd_sample.xml"
    p.write_text(SAMPLE_XML, encoding="utf-8")
    return p


@pytest.fixture()
def cnnvd_gz(tmp_path, cnnvd_xml):
    p = tmp_path / "cnnvd_sample.xml.gz"
    with gzip.open(p, "wt", encoding="utf-8") as f:
        f.write(SAMPLE_XML)
    return p


class TestCnnvdLoader:
    def test_registered(self):
        assert ".xml" in DocumentLoaderRegistry.registered_extensions()
        assert ".xml.gz" in DocumentLoaderRegistry.registered_extensions()

    def test_load_xml(self, cnnvd_xml):
        docs = load_documents(cnnvd_xml)
        assert len(docs) == 2
        d = docs[0]
        # metadata 字段
        assert d.metadata["cnnvd_id"] == "CNNVD-200501-001"
        assert d.metadata["cve_id"] == "CVE-2005-0001"
        assert d.metadata["vendor"] == "Example"
        assert d.metadata["product"] == "web server"
        assert d.metadata["severity"] == "High"  # 高危 -> High
        assert d.metadata["category"] == "cnnvd"
        # 正文含关键内容
        assert "CNNVD编号" in d.page_content
        assert "CVE编号" in d.page_content
        assert "缓冲区溢出" in d.page_content

    def test_load_gz(self, cnnvd_gz):
        docs = load_documents(cnnvd_gz)
        assert len(docs) == 2
        assert docs[0].metadata["file_type"] == "xml.gz"

    def test_missing_fields_tolerated(self, cnnvd_xml):
        """缺失 cve_id/product/severity 的条目不报错，且无空值污染。"""
        docs = load_documents(cnnvd_xml)
        d = docs[1]
        assert d.metadata["cnnvd_id"] == "CNNVD-200501-002"
        assert d.metadata["severity"] == "Info"  # 缺省等级
        assert "CNNVD编号" in d.page_content

    def test_severity_mapping(self):
        from app.rag.loader.cnnvd_loader import CnnvdXmlLoader

        assert CnnvdXmlLoader._map_severity("危急") == "Critical"
        assert CnnvdXmlLoader._map_severity("高危") == "High"
        assert CnnvdXmlLoader._map_severity("中危") == "Medium"
        assert CnnvdXmlLoader._map_severity("低危") == "Low"
        assert CnnvdXmlLoader._map_severity("") == "Info"
