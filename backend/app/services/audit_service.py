"""审计业务服务：项目创建/上传/审计执行/结果落库。

编排链路：
    上传 zip -> ProjectParser 解压 -> VulnerabilityDetector 扫描
    -> Orchestrator 多 Agent 审计 -> 结果落库（task/vuln/repair/agent_logs/report）
"""

from __future__ import annotations

import json
import logging
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from ..agents.orchestrator import Orchestrator
from ..config import settings
from ..models import (
    AgentLog,
    AuditReport,
    AuditTask,
    FileRecord,
    Project,
    RepairSuggestion,
    Vulnerability,
)
from ..security.detector import VulnerabilityDetector
from ..security.project_parser import LANGUAGE_EXTENSIONS, ProjectParser
from .db import get_database

logger = logging.getLogger(__name__)


class AuditServiceError(Exception):
    """审计业务异常。"""


class AuditService:
    """审计业务服务。"""

    def __init__(self, session: Session) -> None:
        self.db = session
        self.work_dir = settings.upload_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)

    # ---------- 项目 ----------
    def create_project(self, user_id: int, name: str, description: str = "") -> Project:
        project = Project(user_id=user_id, name=name, description=description)
        self.db.add(project)
        self.db.commit()
        self.db.refresh(project)
        logger.info("项目创建: id=%d name=%s", project.id, project.name)
        return project

    def get_project(self, project_id: int, user_id: int) -> Optional[Project]:
        return (
            self.db.query(Project)
            .filter(Project.id == project_id, Project.user_id == user_id)
            .first()
        )

    def list_projects(self, user_id: int) -> List[Project]:
        return (
            self.db.query(Project)
            .filter(Project.user_id == user_id)
            .order_by(Project.created_at.desc())
            .all()
        )

    def delete_project(self, project: Project) -> None:
        self.db.delete(project)
        self.db.commit()
        # 清理磁盘目录
        project_dir = self._project_dir(project)
        shutil.rmtree(project_dir, ignore_errors=True)

    def _project_dir(self, project: Project) -> Path:
        return self.work_dir / f"user_{project.user_id}" / f"project_{project.id}"

    # ---------- 上传 ----------
    def upload_zip(self, user_id: int, project: Project, zip_path: Path) -> Dict[str, Any]:
        """解压 zip 到项目目录并登记文件。

        先解压到临时目录，成功后原子替换正式目录；
        解压失败（如恶意 zip）不会破坏已有项目文件。
        """
        target = self._project_dir(project)
        parser = ProjectParser(self.work_dir / f"user_{user_id}")
        temp_name = f"project_{project.id}_uploading"
        # 清理上次失败残留的临时目录
        shutil.rmtree(self.work_dir / f"user_{user_id}" / temp_name, ignore_errors=True)

        extracted = parser.extract_zip(zip_path, temp_name)
        language = parser.detect_language(parser.collect_source_files(extracted))

        # 成功后原子替换
        shutil.rmtree(target, ignore_errors=True)
        extracted.rename(target)

        # 替换后基于正式目录重新收集并登记文件
        files = parser.collect_source_files(target)
        for f in files:
            rel = f.relative_to(target)
            self.db.add(
                FileRecord(
                    project_id=project.id,
                    path=str(rel).replace("\\", "/"),
                    # 未识别扩展名归类为 other（而非空串/unknown）
                    language=LANGUAGE_EXTENSIONS.get(f.suffix.lower(), "other"),
                    size=f.stat().st_size,
                )
            )
        project.language = language
        project.storage_path = str(target)
        self.db.commit()

        logger.info("项目上传完成: %s（%s, %d 文件）", project.name, language, len(files))
        return {"file_count": len(files), "language": language}

    # ---------- 审计 ----------
    def run_audit(self, project: Project, enable_knowledge: bool = True) -> AuditTask:
        """执行完整审计并落库（同步执行；异步化留待后续优化）。"""
        task = AuditTask(
            project_id=project.id,
            task_id=f"task-{uuid.uuid4().hex[:12]}",
            status="running",
            language=project.language,
        )
        self.db.add(task)
        self.db.commit()

        try:
            project_dir = Path(project.storage_path)
            if not project_dir.is_dir():
                raise AuditServiceError(f"项目目录不存在: {project_dir}")

            # 1. 静态扫描
            detector = VulnerabilityDetector()
            scan_result = detector.scan_project(project_dir, project.name)

            # 2. 多 Agent 审计
            orchestrator = Orchestrator()
            result = orchestrator.run_audit(
                scan_result=scan_result.to_dict(),
                project={"name": project.name, "language": project.language},
                # 传递数据库任务 id，保证 Agent 日志（JSONL/执行链）与审计任务 task_id 一致
                task_id=task.task_id,
                enable_knowledge=enable_knowledge,
            )

            # 3. 落库
            report = result.get("report", {})
            summary = report.get("summary", {})
            task.status = "completed"
            task.scanned_files = scan_result.scanned_files
            task.total_findings = summary.get("total_findings", 0)
            task.security_score = summary.get("security_score", 100)
            task.report_json = json.dumps(report, ensure_ascii=False)
            task.finished_at = datetime.now()

            self._save_vulnerabilities(task, report.get("vulnerabilities", []))
            self._save_agent_logs(task, result.get("agent_chain", []))
            self.db.add(
                AuditReport(task_id=task.id, report_format="json", content=task.report_json)
            )
            self.db.commit()
            logger.info("审计完成: task=%s 漏洞=%d", task.task_id, task.total_findings)
            return task
        except Exception as exc:
            task.status = "failed"
            task.error = str(exc)
            task.finished_at = datetime.now()
            self.db.commit()
            logger.exception("审计失败: %s", exc)
            raise

    def _save_vulnerabilities(self, task: AuditTask, vulns: List[Dict[str, Any]]) -> None:
        """保存漏洞与修复建议（Repair Agent 结果与漏洞一一对应）。"""
        for v in vulns:
            vuln = Vulnerability(
                task_id=task.id,
                file_path=v.get("file_path", ""),
                line=v.get("line", 0),
                vulnerability_type=v.get("vulnerability_type", ""),
                severity=v.get("severity", "Medium"),
                cwe_id=v.get("cwe_id"),
                scanner=v.get("scanner", ""),
                rule_id=v.get("rule_id", ""),
                confirmed=bool(v.get("confirmed", True)),
                evidence=v.get("evidence", ""),
                reason=v.get("reason", ""),
            )
            self.db.add(vuln)
            self.db.flush()  # 获取 vuln.id
            # 修复建议
            self.db.add(
                RepairSuggestion(
                    vulnerability_id=vuln.id,
                    root_cause=v.get("root_cause", ""),
                    principle=v.get("repair_principle", ""),
                    suggestion=v.get("repair_suggestion", ""),
                    fixed_code=v.get("fixed_code", ""),
                    references_json=json.dumps(v.get("references", []), ensure_ascii=False),
                    apply_to_source=False,
                )
            )

    def _save_agent_logs(self, task: AuditTask, chain: List[Dict[str, Any]]) -> None:
        """将 Agent 执行链写入 agent_logs 表。"""
        for entry in chain:
            self.db.add(
                AgentLog(
                    audit_task_id=task.id,
                    agent_name=entry.get("agent_name", ""),
                    input_summary=entry.get("input_summary", ""),
                    output_summary=entry.get("output_summary", ""),
                    status=entry.get("status", "completed"),
                    duration=entry.get("duration", 0.0),
                    details_json=json.dumps(entry.get("details", {}), ensure_ascii=False),
                )
            )

    # ---------- 查询 ----------
    def get_task(self, task_id: int) -> Optional[AuditTask]:
        return self.db.query(AuditTask).filter(AuditTask.id == task_id).first()

    def task_belongs_to_user(self, task, user_id: int) -> bool:
        """校验任务归属：任务所属项目是否属于指定用户。"""
        if task is None:
            return False
        project = (
            self.db.query(Project).filter(Project.id == task.project_id).first()
        )
        return project is not None and project.user_id == user_id

    def list_tasks(self, project_id: int, limit: int = 100, offset: int = 0) -> List[AuditTask]:
        return (
            self.db.query(AuditTask)
            .filter(AuditTask.project_id == project_id)
            .order_by(AuditTask.started_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    def get_vulnerabilities(
        self, task_id: int, limit: int = 200, offset: int = 0
    ) -> List[Vulnerability]:
        return (
            self.db.query(Vulnerability)
            .filter(Vulnerability.task_id == task_id)
            .order_by(Vulnerability.severity.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    def get_suggestions(self, vulnerability_id: int) -> List[RepairSuggestion]:
        return (
            self.db.query(RepairSuggestion)
            .filter(RepairSuggestion.vulnerability_id == vulnerability_id)
            .all()
        )

    def get_agent_logs(self, task_id: int) -> List[AgentLog]:
        return (
            self.db.query(AgentLog)
            .filter(AgentLog.audit_task_id == task_id)
            .order_by(AgentLog.id.asc())
            .all()
        )

    def get_report(self, task_id: int) -> Optional[AuditReport]:
        return (
            self.db.query(AuditReport)
            .filter(AuditReport.task_id == task_id)
            .order_by(AuditReport.id.desc())
            .first()
        )
