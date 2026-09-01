"""Audit Agent：代码审计 Agent（毕设路线 7）。

职责：结合"静态扫描结果 + 代码片段 + RAG 安全知识 + LLM"综合判断漏洞。

流程（对每条静态发现）：
    1. 构造审计 Query（漏洞类型 / 规则描述）；
    2. 从上下文获取 Knowledge Agent 已检索的知识（或调用 KnowledgeAgent）；
    3. LLM 分析代码证据，输出结构化判定（漏洞类型 / 风险等级 / 原因 / 证据）；
    4. 归一化风险等级（Critical/High/Medium/Low/Info）。

设计要点：不直接信任静态扫描结果，由 LLM 结合证据与知识二次确认，
避免误报（毕设路线 22 协同思想）。
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from .base import AgentContext, BaseAgent
from .knowledge_agent import KnowledgeAgent
from .llm import parse_json_response

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}


class AuditAgent(BaseAgent):
    """代码审计 Agent。"""

    name = "audit_agent"

    def __init__(self, knowledge_agent: Optional[KnowledgeAgent] = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.knowledge_agent = knowledge_agent or KnowledgeAgent(llm=self.llm)

    def _execute(self, context: AgentContext, **kwargs) -> Dict[str, Any]:
        findings = kwargs.get("findings") or context.get("findings", [])
        if not findings:
            return {"vulnerabilities": [], "count": 0}

        project_info = context.get("project", {})
        results: List[Dict[str, Any]] = []
        for finding in findings:
            results.append(self._analyze_finding(finding, project_info, context))
        return {"vulnerabilities": results, "count": len(results)}

    def _analyze_finding(
        self, finding: Dict[str, Any], project_info: Dict[str, Any], context: AgentContext
    ) -> Dict[str, Any]:
        """分析单个静态发现。"""
        rule_id = finding.get("rule_id", "")
        message = finding.get("message", "")
        snippet = finding.get("code_snippet", "")
        file_path = finding.get("file_path", "")
        scanner = finding.get("scanner", "")

        # 1. 构造检索 Query 并获取知识
        query = f"{message} {rule_id}"
        knowledge_chunks = []
        if context.get("enable_knowledge", True):
            try:
                result = self.knowledge_agent.run(
                    context, query=query, top_k=context.get("knowledge_top_k", 5)
                )
                knowledge_chunks = (result.get("output") or {}).get("chunks", [])
            except Exception as exc:
                logger.warning("知识检索失败（继续审计）: %s", exc)

        # 2. LLM 综合判断
        system_prompt = (
            "你是 Web 代码安全审计专家。基于静态扫描证据、代码片段与安全知识，"
            "判断漏洞是否成立，并输出 JSON："
            '{"confirmed": true/false, "vulnerability_type": "类型", '
            '"severity": "Critical/High/Medium/Low/Info", '
            '"reason": "原因", "evidence": "证据", "cwe_id": "CWE-89"}'
        )
        user_prompt = (
            f"静态扫描结果：scanner={scanner}, rule={rule_id}, message={message}\n"
            f"代码片段：\n```\n{snippet[:1500]}\n```\n"
            f"相关安全知识：\n{self.knowledge_agent.format_knowledge_from_dict(knowledge_chunks)}"
        )
        llm_output = self.llm.chat(system_prompt, user_prompt, max_tokens=800)
        parsed = parse_json_response(llm_output) or {}

        # 3. 归一化风险等级（结合扫描原始等级）
        severity = _normalize_severity(
            parsed.get("severity"), finding.get("severity", "Medium")
        )
        confirmed = bool(parsed.get("confirmed", True))

        return {
            "scanner": scanner,
            "rule_id": rule_id,
            "file_path": file_path,
            "line": finding.get("line", 0),
            "code_snippet": snippet,
            "confirmed": confirmed,
            "vulnerability_type": parsed.get("vulnerability_type") or message[:50],
            "severity": severity,
            "cwe_id": parsed.get("cwe_id") or finding.get("cwe_id"),
            "reason": parsed.get("reason") or "静态扫描发现，需进一步确认",
            "evidence": parsed.get("evidence") or snippet[:200],
            "knowledge_hits": len(knowledge_chunks),
        }


def _normalize_severity(llm_value: Any, fallback: str) -> str:
    """归一化 LLM 输出的风险等级，非法值回退。"""
    if isinstance(llm_value, str):
        value = llm_value.strip().capitalize()
        if value in _SEVERITY_RANK:
            return value
    if isinstance(fallback, str) and fallback.capitalize() in _SEVERITY_RANK:
        return fallback.capitalize()
    return "Medium"
