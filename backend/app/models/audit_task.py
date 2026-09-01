"""审计任务模型。"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..services.db import Base


class AuditTask(Base):
    __tablename__ = "audit_tasks"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True, nullable=False)
    task_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending/running/completed/failed
    language: Mapped[str] = mapped_column(String(32), default="unknown")
    scanned_files: Mapped[int] = mapped_column(Integer, default=0)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    security_score: Mapped[int] = mapped_column(Integer, default=100)
    # 完整报告 JSON（Report Agent 产物）
    report_json: Mapped[str] = mapped_column(Text, default="{}")
    error: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "project_id": self.project_id,
            "task_id": self.task_id,
            "status": self.status,
            "language": self.language,
            "scanned_files": self.scanned_files,
            "total_findings": self.total_findings,
            "security_score": self.security_score,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }
