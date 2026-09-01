"""项目 API：项目管理与代码上传。"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from ..models import Project, User
from ..schemas.api import (
    ProjectCreate,
    ProjectResponse,
    UploadResponse,
)
from ..security.project_parser import ProjectParseError
from ..services.audit_service import AuditService, AuditServiceError
from .deps import get_current_user, get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/projects", tags=["项目"])


@router.get("", response_model=list[ProjectResponse])
def list_projects(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """当前用户的项目列表。"""
    service = AuditService(db)
    return [p.to_dict() for p in service.list_projects(user.id)]


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(
    body: ProjectCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """创建空项目。"""
    service = AuditService(db)
    project = service.create_project(user.id, body.name, body.description)
    return project.to_dict()


@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(
    project_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    service = AuditService(db)
    project = service.get_project(project_id, user.id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="项目不存在")
    return project.to_dict()


@router.post("/{project_id}/upload", response_model=UploadResponse)
async def upload_project(
    project_id: int,
    file: UploadFile = File(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """上传项目代码 zip 包并解压登记。"""
    service = AuditService(db)
    project = service.get_project(project_id, user.id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="项目不存在")

    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="仅支持 zip 格式的项目包")

    # 保存到临时文件后安全解压
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp.write(await file.read())
        tmp_path = Path(tmp.name)
    try:
        result = service.upload_zip(user.id, project, tmp_path)
    except ProjectParseError as exc:
        raise HTTPException(status_code=400, detail=f"项目包解析失败: {exc}") from exc
    finally:
        tmp_path.unlink(missing_ok=True)

    return UploadResponse(
        project_id=project.id,
        name=project.name,
        file_count=result["file_count"],
        language=result["language"],
        message="上传成功",
    )


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    service = AuditService(db)
    project = service.get_project(project_id, user.id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="项目不存在")
    service.delete_project(project)
