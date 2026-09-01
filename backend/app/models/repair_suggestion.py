"""修复建议模型。"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..services.db import Base


class RepairSuggestion(Base):
    __tablename__ = "repair_suggestions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id"), index=True, nullable=False
    )
    root_cause: Mapped[str] = mapped_column(Text, default="")
    principle: Mapped[str] = mapped_column(Text, default="")
    suggestion: Mapped[str] = mapped_column(Text, default="")
    fixed_code: Mapped[str] = mapped_column(Text, default="")
    references_json: Mapped[str] = mapped_column(Text, default="[]")
    apply_to_source: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)

    def to_dict(self) -> dict:
        import json

        try:
            references = json.loads(self.references_json or "[]")
        except ValueError:
            references = []
        return {
            "id": self.id,
            "vulnerability_id": self.vulnerability_id,
            "root_cause": self.root_cause,
            "principle": self.principle,
            "suggestion": self.suggestion,
            "fixed_code": self.fixed_code,
            "references": references,
            "apply_to_source": bool(self.apply_to_source),
        }
