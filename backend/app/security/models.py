"""安全分析数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class ScanFinding:
    """单个扫描发现（静态扫描 / AST / 规则匹配的原始结果）。"""

    scanner: str                # 来源：bandit / semgrep / ast / rule
    rule_id: str                # 规则编号，如 B608 / python.eval / CWE-78
    severity: str               # Critical / High / Medium / Low / Info
    message: str                # 描述
    file_path: str              # 相对项目路径
    line: int = 0               # 行号（0 表示未知）
    code_snippet: str = ""      # 相关代码片段
    cwe_id: Optional[str] = None  # 关联 CWE（尽力映射）
    confidence: str = "Medium"  # High / Medium / Low

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner": self.scanner,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "message": self.message,
            "file_path": self.file_path,
            "line": self.line,
            "code_snippet": self.code_snippet,
            "cwe_id": self.cwe_id,
        }


@dataclass
class ScanResult:
    """一次扫描任务的完整结果。"""

    project_name: str
    language: str
    scanned_files: int = 0
    findings: List[ScanFinding] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.now)
    finished_at: Optional[datetime] = None
    scanner_status: Dict[str, str] = field(default_factory=dict)  # scanner -> ok/skipped/error

    def severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_name": self.project_name,
            "language": self.language,
            "scanned_files": self.scanned_files,
            "total_findings": len(self.findings),
            "severity_counts": self.severity_counts(),
            "scanner_status": self.scanner_status,
            "findings": [f.to_dict() for f in self.findings],
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }
