"""Repair Agent：漏洞修复 Agent（毕设路线 9）。

输入：漏洞信息 + 漏洞代码 + RAG 安全知识。
输出：漏洞原因 / 修复原则 / 修复方案 / 修复后代码。

安全约束：Repair Agent 不直接修改原始代码，只生成修复建议与 Patch，
由用户确认后应用（毕设路线 9 的"原始代码 -> 建议 -> Patch -> 确认"流程）。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from .base import AgentContext, BaseAgent
from .llm import parse_json_response

logger = logging.getLogger(__name__)


class RepairAgent(BaseAgent):
    """修复建议 Agent。"""

    name = "repair_agent"

    def _execute(self, context: AgentContext, **kwargs) -> Dict[str, Any]:
        vulnerabilities = kwargs.get("vulnerabilities") or context.get("vulnerabilities", [])
        knowledge = kwargs.get("knowledge") or context.get("repair_knowledge", {})
        if not vulnerabilities:
            return {"suggestions": [], "count": 0}

        suggestions: List[Dict[str, Any]] = []
        for vuln in vulnerabilities:
            if not vuln.get("confirmed", True):
                continue
            suggestions.append(
                self._repair_one(vuln, knowledge.get(vuln.get("cwe_id") or vuln.get("rule_id")))
            )
        return {"suggestions": suggestions, "count": len(suggestions)}

    def _repair_one(self, vuln: Dict[str, Any], knowledge_text: str) -> Dict[str, Any]:
        """为单个漏洞生成修复建议。"""
        system_prompt = (
            "你是安全修复专家。基于漏洞信息与安全知识，输出修复建议 JSON："
            '{"root_cause": "漏洞原因", "principle": "修复原则", '
            '"suggestion": "修复方案", "fixed_code": "修复后的代码示例", '
            '"references": ["参考"]}'
        )
        user_prompt = (
            f"漏洞类型：{vuln.get('vulnerability_type', '?')}\n"
            f"CWE：{vuln.get('cwe_id', '?')}\n"
            f"风险等级：{vuln.get('severity', '?')}\n"
            f"漏洞代码：\n```\n{vuln.get('code_snippet', '')[:1200]}\n```\n"
            f"相关安全知识：\n{knowledge_text or '（无）'}\n"
        )
        output = self.llm.chat(system_prompt, user_prompt, max_tokens=1200)
        parsed = parse_json_response(output) or {}
        fixed_code = parsed.get("fixed_code", "")
        if not fixed_code:
            # JSON 解析失败兜底：从输出中提取代码块
            fixed_code = _extract_code_block(output)

        return {
            "file_path": vuln.get("file_path", ""),
            "line": vuln.get("line", 0),
            "vulnerability_type": vuln.get("vulnerability_type", ""),
            "cwe_id": vuln.get("cwe_id"),
            "severity": vuln.get("severity", "Medium"),
            "root_cause": parsed.get("root_cause", vuln.get("reason", "")),
            "principle": parsed.get("principle", ""),
            "suggestion": parsed.get("suggestion", output[:300]),
            "fixed_code": fixed_code,
            "references": parsed.get("references", []),
            # 修复约束：不直接改原始代码，输出建议供用户确认
            "apply_to_source": False,
        }


def _extract_code_block(text: str) -> str:
    """从 LLM 输出中提取 ``` 代码块内容（多个时取第一个）。"""
    import re

    matches = re.findall(r"```(?:\w+)?\n(.*?)```", text, re.DOTALL)
    if matches:
        return matches[0].strip()
    return ""
