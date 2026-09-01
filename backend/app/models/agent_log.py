"""Agent 执行日志模型（毕设路线 26 的 agent_logs 表）。"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..services.db import Base


class AgentLog(Base):
    __tablename__ = "agent_logs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    audit_task_id: Mapped[int] = mapped_column(
        ForeignKey("audit_tasks.id"), index=True, nullable=False
    )
    agent_name: Mapped[str] = mapped_column(String(64), nullable=False)
    input_summary: Mapped[str] = mapped_column(Text, default="")
    output_summary: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="completed")
    duration: Mapped[float] = mapped_column(Float, default=0.0)
    details_json: Mapped[str] = mapped_column(Text, default="{}")
    start_time: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)

    def to_dict(self) -> dict:
        import json

        try:
            details = json.loads(self.details_json or "{}")
        except ValueError:
            details = {}
        return {
            "id": self.id,
            "audit_task_id": self.audit_task_id,
            "agent_name": self.agent_name,
            "input_summary": self.input_summary,
            "output_summary": self.output_summary,
            "status": self.status,
            "duration": self.duration,
            "details": details,
            "start_time": self.start_time.isoformat() if self.start_time else None,
        }
