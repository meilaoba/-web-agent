"""漏洞检测模块：汇总多扫描器结果，去重并评级。

职责（毕设路线 21-22 中"静态扫描 + 代码分析"阶段）：
1. 组合执行 Bandit / Semgrep / AST 分析；
2. 去重（相同文件 + 行号 + 规则）；
3. 结果归类到统一 ScanFinding 结构，供 Audit Agent 进一步分析。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional, Sequence

from .ast_analyzer import AstAnalyzer
from .models import ScanFinding, ScanResult
from .project_parser import ProjectParser
from .scanner import BanditScanner, BaseScanner, SemgrepScanner

logger = logging.getLogger(__name__)


class VulnerabilityDetector:
    """组合扫描器执行漏洞检测。"""

    def __init__(self, scanners: Optional[Sequence[BaseScanner]] = None) -> None:
        self.scanners: List[BaseScanner] = list(scanners) if scanners else [
            BanditScanner(),
            SemgrepScanner(),
            AstAnalyzer(),
        ]

    def scan_project(
        self,
        project_dir: Path | str,
        project_name: str,
        parser: Optional[ProjectParser] = None,
    ) -> ScanResult:
        """扫描项目目录，返回汇总结果。"""
        root = Path(project_dir)
        parser = parser or ProjectParser(root.parent)
        files = parser.collect_source_files(root)
        language = parser.detect_language(files)

        result = ScanResult(project_name=project_name, language=language, scanned_files=len(files))
        all_findings: List[ScanFinding] = []

        for scanner in self.scanners:
            try:
                if not scanner.available():
                    result.scanner_status[scanner.name] = "skipped"
                    logger.info("扫描器 %s 不可用，已跳过", scanner.name)
                    continue
                findings = scanner.scan(files, root)
                result.scanner_status[scanner.name] = f"ok({len(findings)})"
                all_findings.extend(findings)
            except Exception as exc:  # 单扫描器失败不阻断整体
                result.scanner_status[scanner.name] = f"error: {exc}"
                logger.error("扫描器 %s 执行失败: %s", scanner.name, exc)

        result.findings = _dedupe(all_findings)
        result.finished_at = __import__("datetime").datetime.now()
        logger.info(
            "漏洞检测完成: %s（%s）共 %d 个文件，原始发现 %d 条，去重后 %d 条",
            project_name,
            language,
            result.scanned_files,
            len(all_findings),
            len(result.findings),
        )
        return result


def _dedupe(findings: List[ScanFinding]) -> List[ScanFinding]:
    """按 (file, line, rule_id, message) 去重，保留首次出现。"""
    seen = set()
    unique: List[ScanFinding] = []
    for f in findings:
        key = (f.file_path, f.line, f.rule_id, f.message[:50])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique
