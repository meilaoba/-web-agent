"""静态安全扫描器模块。

设计（毕设路线 21：静态扫描 -> Agent 进一步分析）：
- BaseScanner 抽象基类，业务只依赖该接口；
- BanditScanner：Python 安全扫描（bandit CLI，JSON 输出解析）；
- SemgrepScanner：通用多语言规则扫描（semgrep CLI，可插拔，未安装时自动跳过）；
- 新增扫描器只需继承 BaseScanner 并注册。

扫描结果统一为 ScanFinding，由上层漏洞检测模块汇总。
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional

from .models import ScanFinding

logger = logging.getLogger(__name__)

#: bandit severity -> 统一等级
_BANDIT_SEVERITY_MAP = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNDEFINED": "Info"}
#: bandit 常见规则 -> CWE 近似映射（审计辅助）
_BANDIT_CWE_MAP = {
    "B608": "CWE-89",   # SQL 注入
    "B602": "CWE-78",   # shell 注入
    "B605": "CWE-78",
    "B607": "CWE-78",
    "B601": "CWE-78",
    "B110": "CWE-502",  # pickle
    "B301": "CWE-502",
    "B307": "CWE-78",
    "B322": "CWE-502",
    "B201": "CWE-319",  # flask debug
    "B506": "CWE-502",  # yaml load
    "B404": "CWE-78",   # subprocess import
    "B602": "CWE-78",
}


class ScannerError(Exception):
    """扫描器执行异常。"""


class BaseScanner(ABC):
    """扫描器抽象基类。"""

    name: str = "base"

    @abstractmethod
    def scan(self, files: List[Path], project_root: Path) -> List[ScanFinding]:
        """扫描文件列表，返回发现列表。"""

    @classmethod
    def available(cls) -> bool:
        """扫描器是否可用（依赖 / CLI 是否就绪）。"""
        return True


class BanditScanner(BaseScanner):
    """Bandit Python 安全扫描器。"""

    name = "bandit"

    def __init__(self, timeout: int = 120) -> None:
        self.timeout = timeout

    @classmethod
    def available(cls) -> bool:
        try:
            import bandit  # noqa: F401

            return True
        except ImportError:
            return False

    def scan(self, files: List[Path], project_root: Path) -> List[ScanFinding]:
        py_files = [f for f in files if f.suffix.lower() == ".py"]
        if not py_files:
            return []
        try:
            import bandit
        except ImportError:
            logger.warning("Bandit 未安装，跳过 bandit 扫描")
            return []

        # 使用 bandit Python API（避免依赖 CLI 可执行文件）
        from bandit.core import manager, config as b_config

        project_dir = str(project_root)
        cfg = b_config.BanditConfig()
        mgr = manager.BanditManager(cfg, agg_type="file", debug=False, verbose=False, quiet=True)
        mgr.discover_files([project_dir], True)
        mgr.run_tests()
        results: List[ScanFinding] = []
        for issue in mgr.get_issue_list():
            fname = getattr(issue, "fname", None) or getattr(issue, "filename", None)
            if not fname:
                continue
            rel = _relative(fname, project_dir)
            # bandit 1.9: severity/confidence 为字符串（'HIGH'/'LOW'）
            severity = str(getattr(issue, "severity", "UNDEFINED") or "UNDEFINED").upper()
            confidence = str(getattr(issue, "confidence", "MEDIUM") or "MEDIUM").upper()
            cwe = getattr(issue, "cwe", None)
            cwe_id = f"CWE-{cwe.id}" if cwe and getattr(cwe, "id", None) else None
            results.append(
                ScanFinding(
                    scanner=self.name,
                    rule_id=str(getattr(issue, "test_id", "") or ""),
                    severity=_BANDIT_SEVERITY_MAP.get(severity, "Medium"),
                    confidence=confidence.title(),
                    message=str(getattr(issue, "text", "") or ""),
                    file_path=rel,
                    line=int(getattr(issue, "lineno", 0) or 0),
                    code_snippet=str(getattr(issue, "get_code", lambda: "")() or "")[:500],
                    cwe_id=cwe_id or _BANDIT_CWE_MAP.get(str(getattr(issue, "test_id", "") or "")),
                )
            )
        logger.info("Bandit 扫描完成: %d 条发现", len(results))
        return results


class SemgrepScanner(BaseScanner):
    """Semgrep 规则扫描器（可插拔）。

    需要 semgrep CLI 可用（pip install semgrep）。
    未安装时 available() 返回 False，上层自动跳过（不阻断流程）。
    """

    name = "semgrep"

    def __init__(self, timeout: int = 180, rules: Optional[List[str]] = None) -> None:
        self.timeout = timeout
        # 默认使用 semgrep 内置的安全规则集（p/owasp-top-ten）
        self.rules = rules or ["p/owasp-top-ten"]

    @classmethod
    def available(cls) -> bool:
        return shutil.which("semgrep") is not None

    def scan(self, files: List[Path], project_root: Path) -> List[ScanFinding]:
        if not self.available():
            logger.warning("semgrep CLI 不可用，跳过 semgrep 扫描（pip install semgrep 启用）")
            return []

        cmd = [
            "semgrep",
            "--json",
            "--quiet",
            "--no-rewrite-rule-ids",
            "-c",
            self.rules[0],
            str(project_root),
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.error("semgrep 执行失败: %s", exc)
            return []

        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            logger.error("semgrep 输出解析失败")
            return []

        results: List[ScanFinding] = []
        for r in payload.get("results", []):
            path = str(r.get("path", ""))
            rel = _relative(path, str(project_root))
            sev = str(r.get("extra", {}).get("severity", "WARNING")).upper()
            results.append(
                ScanFinding(
                    scanner=self.name,
                    rule_id=str(r.get("check_id", "")),
                    severity=_BANDIT_SEVERITY_MAP.get(sev, "Medium"),
                    confidence="Medium",
                    message=str(r.get("extra", {}).get("message", ""))[:500],
                    file_path=rel,
                    line=int(r.get("start", {}).get("line", 0)),
                    code_snippet=str(r.get("extra", {}).get("lines", ""))[:500],
                )
            )
        logger.info("Semgrep 扫描完成: %d 条发现", len(results))
        return results


def _relative(path: str, base: str) -> str:
    """将绝对路径转为相对 base 的路径。"""
    try:
        return str(Path(path).resolve().relative_to(Path(base).resolve()))
    except ValueError:
        return path
