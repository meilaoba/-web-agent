"""Orchestrator 主 Agent（毕设路线 6）。

职责：
1. 接收审计任务；
2. 调度 Audit / Knowledge / Repair / Report Agent；
3. 管理执行顺序与结果流转；
4. 汇总最终报告。

完整协同流程（毕设路线 5）：
    Orchestrator → AuditAgent → KnowledgeAgent(RAG) → AuditAgent(综合判断)
    → RepairAgent → ReportAgent
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

from .agent_log import AgentLogger, get_agent_logger
from .audit_agent import AuditAgent
from .base import AgentContext, BaseAgent
from .knowledge_agent import KnowledgeAgent
from .repair_agent import RepairAgent
from .report_agent import ReportAgent

logger = logging.getLogger(__name__)


class Orchestrator(BaseAgent):
    """审计任务编排器。"""

    name = "orchestrator"

    def __init__(
        self,
        audit_agent: Optional[AuditAgent] = None,
        knowledge_agent: Optional[KnowledgeAgent] = None,
        repair_agent: Optional[RepairAgent] = None,
        report_agent: Optional[ReportAgent] = None,
        agent_logger: Optional[AgentLogger] = None,
        **kwargs,
    ) -> None:
        super().__init__(agent_logger=agent_logger, **kwargs)
        # 子 Agent 共享 LLM 与日志器；默认构造时使用全局单例日志器，
        # 保证子 Agent 的执行记录进入同一任务日志
        effective_logger = self.agent_logger or get_agent_logger()
        self.audit_agent = audit_agent or AuditAgent(llm=self.llm, agent_logger=effective_logger)
        self.knowledge_agent = knowledge_agent or KnowledgeAgent(llm=self.llm, agent_logger=effective_logger)
        self.repair_agent = repair_agent or RepairAgent(llm=self.llm, agent_logger=effective_logger)
        self.report_agent = report_agent or ReportAgent(llm=self.llm, agent_logger=effective_logger)

    def _execute(self, context: AgentContext, **kwargs) -> Dict[str, Any]:
        """执行完整审计流程。"""
        # 供外部直接调用的便捷入口
        return self.run_audit(
            scan_result=kwargs.get("scan_result") or context.get("scan_result", {}),
            project=kwargs.get("project") or context.get("project", {}),
            task_id=context.task_id,
            enable_knowledge=kwargs.get("enable_knowledge", context.get("enable_knowledge", True)),
        )

    def run_audit(
        self,
        scan_result: Dict[str, Any],
        project: Optional[Dict[str, Any]] = None,
        *,
        task_id: Optional[str] = None,
        enable_knowledge: bool = True,
    ) -> Dict[str, Any]:
        """编排完整审计任务，返回报告 + 执行链日志。"""
        logger_obj = self.agent_logger or get_agent_logger()
        tid = logger_obj.start_task(task_id)
        context = AgentContext(tid, {
            "project": project or {},
            "scan_result": scan_result,
            "findings": scan_result.get("findings", []),
            "enable_knowledge": enable_knowledge,
        })
        start = time.time()
        project_name = (project or {}).get("name", "?")
        logger_obj.log(
            tid, self.name,
            f"审计任务开始: {project_name}（发现 {len(scan_result.get('findings', []))} 条）",
            status="running",
        )
        logger.info("[%s] 审计任务开始: %s", tid, project_name)

        # 1. Audit Agent：静态发现 -> 漏洞判定（内部调用 Knowledge Agent 获取知识）
        audit_result = self.audit_agent.run(context)
        vulnerabilities = (audit_result.get("output") or {}).get("vulnerabilities", [])
        confirmed = [v for v in vulnerabilities if v.get("confirmed", True)]
        logger.info("[%s] 审计完成: %d 条发现 -> %d 条确认漏洞", tid, len(vulnerabilities), len(confirmed))

        # 2. 知识补充：为每个已确认漏洞收集 RAG 知识（供修复使用）
        knowledge_map: Dict[str, Any] = {}
        if enable_knowledge:
            for vuln in confirmed:
                cwe = vuln.get("cwe_id")
                rule = vuln.get("rule_id")
                try:
                    res = self.knowledge_agent.run(
                        context,
                        query=f"{vuln.get('vulnerability_type', '')} {vuln.get('reason', '')}",
                        cwe_id=cwe,
                        top_k=3,
                    )
                    chunks = (res.get("output") or {}).get("chunks", [])
                    knowledge_map[cwe or rule or "generic"] = (
                        self.knowledge_agent.format_knowledge_from_dict(chunks)
                    )
                except Exception as exc:
                    logger.warning("[%s] 知识补充失败: %s", tid, exc)
            context.set("repair_knowledge", knowledge_map)

        # 3. Repair Agent：生成修复建议
        repair_result = self.repair_agent.run(context, vulnerabilities=confirmed)
        suggestions = (repair_result.get("output") or {}).get("suggestions", [])

        # 4. Report Agent：生成报告
        context.update({
            "vulnerabilities": confirmed,
            "suggestions": suggestions,
        })
        report_result = self.report_agent.run(context)
        report = report_result.get("output", {})

        # 5. 汇总执行链
        chain = logger_obj.get_task_logs(tid)
        duration = round(time.time() - start, 3)
        logger_obj.log(
            tid, self.name,
            "汇总各 Agent 结果",
            f"审计完成：{len(confirmed)} 条确认漏洞，报告已生成",
            status="completed",
            duration=duration,
        )
        logger.info("[%s] 审计任务完成，耗时 %.2fs", tid, duration)

        return {
            "task_id": tid,
            "status": "completed",
            "duration": duration,
            "report": report,
            "agent_chain": chain,
        }
