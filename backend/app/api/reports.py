"""安全报告 API。"""

from __future__ import annotations

import json
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from ..models import User
from ..services.audit_service import AuditService
from .deps import get_current_user, get_db

router = APIRouter(prefix="/api/reports", tags=["报告"])


@router.get("/tasks/{task_id}")
def get_report(
    task_id: int,
    fmt: str = "json",
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """获取审计报告（fmt=json | markdown）。"""
    service = AuditService(db)
    task = service.get_task(task_id)
    if task is None or not service.task_belongs_to_user(task, user.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="任务不存在")

    try:
        report: Dict = json.loads(task.report_json or "{}")
    except json.JSONDecodeError:
        report = {}

    if fmt == "markdown":
        md = _to_markdown(report)
        return Response(content=md, media_type="text/markdown; charset=utf-8")

    return report


def _to_markdown(report: Dict) -> str:
    """报告转 Markdown（供前端展示 / 导出）。"""
    project = report.get("project", {})
    summary = report.get("summary", {})
    lines = [
        f"# 安全审计报告：{project.get('name', '未知项目')}",
        "",
        f"- 生成时间：{report.get('generated_at', '')}",
        f"- 语言：{project.get('language', 'unknown')}",
        f"- 扫描文件数：{project.get('scanned_files', 0)}",
        f"- 漏洞总数：{summary.get('total_findings', 0)}",
        f"- 安全评分：{summary.get('security_score', 100)}",
        "",
        "## 总体评价",
        "",
        report.get("overall_comment", ""),
        "",
        "## 漏洞详情",
        "",
    ]
    fence = _CODE_FENCE.get(project.get("language", ""), "")
    for v in report.get("vulnerabilities", []):
        lines.append(
            f"### {v.get('severity', 'Info')} | {v.get('vulnerability_type', '?')}"
            f" | {v.get('cwe_id', '')}"
        )
        lines.append(f"- 位置：{v.get('file_path', '')}:{v.get('line', 0)}")
        lines.append(f"- 证据：{v.get('evidence', '')}")
        lines.append(f"- 原因：{v.get('reason', '')}")
        if v.get("repair_suggestion"):
            lines.append(f"- 修复建议：{v['repair_suggestion']}")
        if v.get("fixed_code"):
            lines.append("")
            lines.append(f"```{fence}")
            lines.append(v["fixed_code"])
            lines.append("```")
        lines.append("")
    return "\n".join(lines)


#: 报告代码块语言映射（按项目主语言选择，缺省为无语言标注）
_CODE_FENCE = {
    "python": "python",
    "java": "java",
    "javascript": "javascript",
    "typescript": "typescript",
    "php": "php",
    "go": "go",
    "ruby": "ruby",
    "c": "c",
    "cpp": "cpp",
    "csharp": "csharp",
    "sql": "sql",
    "shell": "bash",
    "powershell": "powershell",
    "html": "html",
    "css": "css",
}
