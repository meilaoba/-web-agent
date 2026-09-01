"""漏洞与修复建议 API。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..models import User
from ..schemas.api import RepairSuggestionResponse, VulnerabilityResponse
from ..services.audit_service import AuditService
from .deps import get_current_user, get_db

router = APIRouter(prefix="/api/vulnerabilities", tags=["漏洞"])


@router.get("", response_model=list[VulnerabilityResponse])
def list_vulnerabilities(
    task_id: int,
    limit: int = Query(200, ge=1, le=1000, description="返回条数上限"),
    offset: int = Query(0, ge=0, description="跳过条数（分页偏移）"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """按审计任务查询漏洞列表（支持 limit/offset 分页）。"""
    service = AuditService(db)
    task = service.get_task(task_id)
    if task is None or not service.task_belongs_to_user(task, user.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="任务不存在")
    return [v.to_dict() for v in service.get_vulnerabilities(task_id, limit=limit, offset=offset)]


@router.get("/{vulnerability_id}/suggestions", response_model=list[RepairSuggestionResponse])
def get_repair_suggestions(
    vulnerability_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """查询漏洞的修复建议。"""
    from ..models import Vulnerability

    service = AuditService(db)
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
    if vuln is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="漏洞不存在")
    task = service.get_task(vuln.task_id)
    if task is None or not service.task_belongs_to_user(task, user.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="无权限访问")
    return [s.to_dict() for s in service.get_suggestions(vulnerability_id)]
