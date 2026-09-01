"""Multi-Agent 模块测试（使用 MockLLM，离线可运行）。"""

from __future__ import annotations

import pytest

from app.agents.agent_log import AgentLogger
from app.agents.audit_agent import AuditAgent
from app.agents.base import AgentContext
from app.agents.knowledge_agent import KnowledgeAgent
from app.agents.llm import MockLLM, get_llm_client, parse_json_response
from app.agents.orchestrator import Orchestrator
from app.agents.repair_agent import RepairAgent
from app.agents.report_agent import ReportAgent
from app.rag.embedding import HashingEmbeddingProvider
from app.rag.retriever import Retriever
from app.rag.schemas import Document
from app.rag.vector_store import ChromaVectorStore
from app.security.detector import VulnerabilityDetector


@pytest.fixture()
def mock_llm():
    return MockLLM()


@pytest.fixture()
def kb_store(tmp_path):
    """临时知识库（含 SQL 注入知识）。"""
    store = ChromaVectorStore(tmp_path / "chroma", "test_kb")
    provider = HashingEmbeddingProvider(dimension=128)
    doc = Document(
        page_content="CWE-89 SQL 注入：必须使用参数化查询 PreparedStatement，禁止字符串拼接 SQL。",
        metadata={
            "chunk_id": "kb-sqli-0001",
            "source": "/kb/sql_injection.md",
            "document_name": "sql_injection.md",
            "category": "owasp_cwe",
            "cwe_id": ["CWE-89"],
        },
    )
    store.add_documents([doc], provider.embed_texts([doc.page_content]))
    return store


@pytest.fixture()
def vuln_scan_result():
    """构造含漏洞的静态扫描结果。"""
    detector = VulnerabilityDetector()
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "vuln.py"
        p.write_text(
            "import subprocess\n"
            "def run(x):\n"
            "    return subprocess.run(f'ping {x}', shell=True)\n",
            encoding="utf-8",
        )
        result = detector.scan_project(tmp, "demo")
        return result.to_dict()


class TestMockLLM:
    def test_rule_responses(self):
        llm = MockLLM()
        assert "SQL" in llm.chat("sys", "sql 注入 拼接")
        assert "CWE-89" in llm.chat("sys", "sql 注入 拼接")
        assert "CWE-502" in llm.chat("sys", "pickle 反序列化")

    def test_parse_json_response(self):
        assert parse_json_response('{"a": 1}') == {"a": 1}
        assert parse_json_response('```json\n{"a": 1}\n```') == {"a": 1}
        assert parse_json_response("no json") is None


class TestAgentLog:
    def test_log_and_read(self, tmp_path):
        logger_obj = AgentLogger(tmp_path)
        tid = logger_obj.start_task()
        logger_obj.log(tid, "audit_agent", "input1", "output1")
        logger_obj.log(tid, "report_agent", "input2", "output2", status="completed", duration=1.5)
        entries = logger_obj.get_task_logs(tid)
        assert len(entries) == 2
        assert entries[0]["agent_name"] == "audit_agent"
        assert entries[1]["duration"] == 1.5
        # 文件持久化
        file_entries = logger_obj.read_task_file(tid)
        assert len(file_entries) == 2


class TestKnowledgeAgent:
    def test_retrieve_knowledge(self, kb_store, mock_llm):
        agent = KnowledgeAgent(
            llm=mock_llm,
            retriever=Retriever(kb_store, HashingEmbeddingProvider(dimension=128), default_top_k=3),
        )
        context = AgentContext("t1")
        result = agent.run(context, query="SQL 注入 如何修复", top_k=3)
        output = result["output"]
        assert output["count"] >= 1
        assert "CWE-89" in output["chunks"][0]["metadata"]["cwe_id"]

    def test_search_by_cwe(self, kb_store, mock_llm):
        agent = KnowledgeAgent(
            llm=mock_llm,
            retriever=Retriever(kb_store, HashingEmbeddingProvider(dimension=128), default_top_k=3),
        )
        context = AgentContext("t1")
        result = agent.run(context, cwe_id="CWE-89", top_k=3)
        assert result["output"]["count"] >= 1


class TestAuditAgent:
    def test_analyze_findings(self, mock_llm, kb_store, vuln_scan_result):
        agent = AuditAgent(
            llm=mock_llm,
            knowledge_agent=KnowledgeAgent(
                llm=mock_llm,
                retriever=Retriever(kb_store, HashingEmbeddingProvider(dimension=128), default_top_k=3),
            ),
        )
        context = AgentContext("t1", {"enable_knowledge": True})
        result = agent.run(context, findings=vuln_scan_result["findings"])
        output = result["output"]
        assert output["count"] >= 1
        vuln = output["vulnerabilities"][0]
        assert vuln["severity"] in ("Critical", "High", "Medium", "Low", "Info")
        assert "file_path" in vuln


class TestRepairAgent:
    def test_generate_suggestion(self, mock_llm):
        agent = RepairAgent(llm=mock_llm)
        context = AgentContext("t1")
        vulns = [{
            "confirmed": True,
            "vulnerability_type": "SQL Injection",
            "cwe_id": "CWE-89",
            "severity": "High",
            "code_snippet": 'cur.execute("SELECT * FROM users WHERE id=" + uid)',
            "file_path": "app.py",
            "line": 5,
        }]
        result = agent.run(context, vulnerabilities=vulns)
        output = result["output"]
        assert output["count"] == 1
        sug = output["suggestions"][0]
        assert sug["apply_to_source"] is False  # 不直接修改源码
        assert "PreparedStatement" in sug["fixed_code"] or "?" in sug["fixed_code"]


class TestReportAgent:
    def test_build_report(self, mock_llm):
        agent = ReportAgent(llm=mock_llm)
        context = AgentContext("t1")
        result = agent.run(
            context,
            vulnerabilities=[{
                "confirmed": True,
                "vulnerability_type": "SQL Injection",
                "cwe_id": "CWE-89",
                "severity": "High",
                "file_path": "app.py",
                "line": 5,
                "evidence": "拼接",
                "reason": "拼接 SQL",
            }],
            suggestions=[],
            scan_result={"language": "python", "scanned_files": 3},
            project={"name": "demo"},
        )
        report = result["output"]
        assert report["summary"]["severity_counts"]["High"] == 1
        assert report["summary"]["security_score"] == 85
        assert report["project"]["name"] == "demo"
        assert len(report["vulnerabilities"]) == 1


class TestOrchestrator:
    def test_full_audit_flow(self, mock_llm, kb_store, vuln_scan_result, tmp_path):
        """端到端：扫描结果 -> 多 Agent 协同 -> 报告 + 执行链。"""
        retriever = Retriever(kb_store, HashingEmbeddingProvider(dimension=128), default_top_k=3)
        orchestrator = Orchestrator(
            llm=mock_llm,
            knowledge_agent=KnowledgeAgent(llm=mock_llm, retriever=retriever),
            agent_logger=AgentLogger(tmp_path / "logs"),
        )
        result = orchestrator.run_audit(
            scan_result=vuln_scan_result,
            project={"name": "demo"},
        )
        assert result["status"] == "completed"
        assert result["report"]["project"]["name"] == "demo"
        assert "vulnerabilities" in result["report"]
        # 执行链完整：orchestrator/audit/knowledge/repair/report 均有记录
        agents = {e["agent_name"] for e in result["agent_chain"]}
        assert "orchestrator" in agents
        assert "audit_agent" in agents
        assert "repair_agent" in agents
        assert "report_agent" in agents
