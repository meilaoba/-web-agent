"""安全报告模型。"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..services.db import Base


class AuditReport(Base):
    __tablename__ = "audit_reports"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("audit_tasks.id"), index=True, nullable=False)
    report_format: Mapped[str] = mapped_column(String(16), default="json")  # json/markdown
    content: Mapped[str] = mapped_column(Text, default="{}")
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "task_id": self.task_id,
            "report_format": self.report_format,
            "content": self.content,
            "generated_at": self.generated_at.isoformat() if self.generated_at else None,
        }
