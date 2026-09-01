"""Agent 执行过程 API。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..models import User
from ..schemas.api import AgentLogResponse
from ..services.audit_service import AuditService
from .deps import get_current_user, get_db

router = APIRouter(prefix="/api/agents", tags=["Agent"])


@router.get("/tasks/{task_id}/logs", response_model=list[AgentLogResponse])
def get_agent_logs(
    task_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """获取任务的 Agent 执行过程（执行链）。"""
    service = AuditService(db)
    task = service.get_task(task_id)
    if task is None or not service.task_belongs_to_user(task, user.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="任务不存在")
    return [a.to_dict() for a in service.get_agent_logs(task_id)]
