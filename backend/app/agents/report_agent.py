"""Report Agent：安全报告生成 Agent（毕设路线 10）。

汇总全部 Agent 结果，输出：
- 项目基本信息 / 扫描统计 / 漏洞等级统计
- 漏洞详情（位置/证据/CWE/OWASP/原因/修复建议/修复代码）
- 安全评分与总体评价
输出格式：JSON（可渲染为 Web/Markdown 报告）。
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List

from .base import AgentContext, BaseAgent

logger = logging.getLogger(__name__)

#: 安全评分权重（按风险等级扣分）
_SEVERITY_SCORE = {"Critical": -30, "High": -15, "Medium": -8, "Low": -3, "Info": -1}


class ReportAgent(BaseAgent):
    """报告生成 Agent。"""

    name = "report_agent"

    def _execute(self, context: AgentContext, **kwargs) -> Dict[str, Any]:
        vulnerabilities = kwargs.get("vulnerabilities") or context.get("vulnerabilities", [])
        suggestions = kwargs.get("suggestions") or context.get("suggestions", [])
        scan_result = kwargs.get("scan_result") or context.get("scan_result", {})
        project = kwargs.get("project") or context.get("project", {})

        severity_counts: Dict[str, int] = {}
        for v in vulnerabilities:
            sev = v.get("severity", "Info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        score = self._compute_score(severity_counts)
        suggestion_map = {
            f"{s.get('file_path')}:{s.get('line')}": s for s in suggestions
        }

        details: List[Dict[str, Any]] = []
        for v in vulnerabilities:
            key = f"{v.get('file_path')}:{v.get('line')}"
            repair = suggestion_map.get(key, {})
            details.append({
                "file_path": v.get("file_path", ""),
                "line": v.get("line", 0),
                "vulnerability_type": v.get("vulnerability_type", ""),
                "severity": v.get("severity", "Info"),
                "cwe_id": v.get("cwe_id"),
                "confirmed": v.get("confirmed", True),
                "evidence": v.get("evidence", ""),
                "reason": v.get("reason", ""),
                "root_cause": repair.get("root_cause", ""),
                "repair_principle": repair.get("principle", ""),
                "repair_suggestion": repair.get("suggestion", ""),
                "fixed_code": repair.get("fixed_code", ""),
            })

        # 总体评价（规则化 + LLM 摘要可选）
        overall = self._overall_comment(score, severity_counts)
        report = {
            "project": {
                "name": project.get("name", "未知项目"),
                "language": scan_result.get("language", "unknown"),
                "scanned_files": scan_result.get("scanned_files", 0),
            },
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "summary": {
                "total_findings": len(vulnerabilities),
                "severity_counts": severity_counts,
                "security_score": score,
            },
            "overall_comment": overall,
            "vulnerabilities": details,
        }
        return report

    @staticmethod
    def _compute_score(severity_counts: Dict[str, int]) -> int:
        """安全评分：100 起扣，最低 0。"""
        score = 100
        for sev, count in severity_counts.items():
            score += _SEVERITY_SCORE.get(sev, 0) * count
        return max(0, min(100, score))

    @staticmethod
    def _overall_comment(score: int, counts: Dict[str, int]) -> str:
        if score >= 90:
            return "整体安全性良好，未发现严重风险，建议保持现有防护措施。"
        if score >= 70:
            return (
                f"存在 {counts.get('Medium', 0)} 个中危风险，"
                "建议优先修复可被远程利用的漏洞。"
            )
        if score >= 50:
            return (
                f"存在 {counts.get('High', 0)} 个高危风险，"
                "建议尽快修复并重新审计。"
            )
        return (
            f"存在 {counts.get('Critical', 0)} 个严重风险，"
            "系统面临较高安全威胁，必须立即修复。"
        )
