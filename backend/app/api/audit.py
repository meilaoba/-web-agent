"""审计 API：创建任务 / 查询状态 / 获取结果。"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..models import User
from ..schemas.api import (
    AuditCreate,
    AuditResultResponse,
    AuditStatusResponse,
)
from ..services.audit_service import AuditService, AuditServiceError

logger = logging.getLogger(__name__)
from .deps import get_current_user, get_db

router = APIRouter(prefix="/api/audit", tags=["审计"])


@router.post("/tasks", response_model=AuditStatusResponse, status_code=status.HTTP_201_CREATED)
def create_audit_task(
    body: AuditCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """对项目执行完整审计（同步；返回任务状态）。"""
    service = AuditService(db)
    project = service.get_project(body.project_id, user.id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="项目不存在")
    try:
        task = service.run_audit(project, enable_knowledge=body.enable_knowledge)
    except AuditServiceError as exc:
        # 业务层可预期错误（如项目目录缺失），给出可读信息
        logger.warning("审计业务失败: %s", exc)
        raise HTTPException(status_code=400, detail=f"审计执行失败: {exc}") from exc
    except Exception as exc:
        # 未知异常：记录日志，不向前端泄露内部细节
        logger.exception("审计执行发生未知异常: %s", exc)
        raise HTTPException(status_code=500, detail="审计执行失败，请稍后重试或查看服务端日志") from exc
    return task.to_dict()


@router.get("/tasks", response_model=list[AuditStatusResponse])
def list_audit_tasks(
    project_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """项目的审计任务列表。"""
    service = AuditService(db)
    project = service.get_project(project_id, user.id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="项目不存在")
    return [t.to_dict() for t in service.list_tasks(project_id, limit=limit, offset=offset)]


@router.get("/tasks/{task_id}", response_model=AuditStatusResponse)
def get_audit_task(
    task_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    service = AuditService(db)
    task = service.get_task(task_id)
    if task is None or not service.task_belongs_to_user(task, user.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="任务不存在")
    return task.to_dict()


@router.get("/tasks/{task_id}/result", response_model=AuditResultResponse)
def get_audit_result(
    task_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """获取审计完整结果（报告 + Agent 执行链）。"""
    service = AuditService(db)
    task = service.get_task(task_id)
    if task is None or not service.task_belongs_to_user(task, user.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="任务不存在")

    report = {}
    try:
        report = json.loads(task.report_json or "{}")
    except json.JSONDecodeError:
        pass

    agent_logs = service.get_agent_logs(task_id)
    return AuditResultResponse(
        task_id=task.task_id,
        status=task.status,
        duration=0.0,
        report=report,
        agent_chain=[a.to_dict() for a in agent_logs],
    )
