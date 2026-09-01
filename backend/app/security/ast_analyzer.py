"""AST 代码分析器（Python）。

基于 Python 标准库 ast 模块做结构分析，检测常见危险模式：
- eval / exec 动态执行
- 命令执行：os.system / os.popen / subprocess(shell=True) / 命令拼接
- 不安全反序列化：pickle.loads / yaml.load
- SQL 字符串拼接：execute/executemany 拼接（+ / f-string / %）
- SSTI：render_template_string
- SSRF 提示：用户输入流向 requests.get

与静态扫描器互补：静态工具发现可疑代码，AST 提供结构证据，
LLM/Agent 负责语义理解与综合判断（毕设路线 22）。
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .models import ScanFinding

logger = logging.getLogger(__name__)


@dataclass
class _Pattern:
    """AST 分析模式。"""

    rule_id: str
    message: str
    severity: str
    cwe_id: Optional[str]
    #: 匹配函数名（含模块前缀，如 os.system）
    function_names: tuple[str, ...] = ()
    #: 匹配属性名（如 .execute）
    attr_names: tuple[str, ...] = ()
    #: 需要 shell 关键字（subprocess）
    require_shell_keyword: bool = False


#: 规则表（新增规则只需在此追加）
PATTERNS: List[_Pattern] = [
    _Pattern("python.eval", "检测到 eval 动态执行，可能执行不可信代码", "High", "CWE-95",
             function_names=("eval",)),
    _Pattern("python.exec", "检测到 exec 动态执行，可能执行不可信代码", "High", "CWE-95",
             function_names=("exec",)),
    _Pattern("python.os_system", "检测到 os.system 执行系统命令，注意命令注入风险", "High", "CWE-78",
             function_names=("os.system",)),
    _Pattern("python.os_popen", "检测到 os.popen 执行系统命令，注意命令注入风险", "High", "CWE-78",
             function_names=("os.popen",)),
    _Pattern("python.subprocess_shell", "subprocess 使用 shell=True，注意命令注入风险", "High", "CWE-78",
             function_names=("subprocess.run", "subprocess.call", "subprocess.Popen",
                             "subprocess.check_output", "subprocess.check_call"),
             require_shell_keyword=True),
    _Pattern("python.pickle_loads", "pickle.loads 反序列化不可信数据可能导致 RCE", "High", "CWE-502",
             function_names=("pickle.loads",)),
    _Pattern("python.yaml_load", "yaml.load 默认构造任意对象，存在反序列化风险（改用 safe_load）", "High", "CWE-502",
             function_names=("yaml.load",)),
    _Pattern("python.sql_concat", "SQL 查询疑似字符串拼接（execute 参数含拼接），存在注入风险", "High", "CWE-89",
             attr_names=("execute", "executemany", "executescript")),
    _Pattern("python.ssti", "render_template_string 渲染模板字符串，注意 SSTI 风险", "Medium", "CWE-1336",
             function_names=("render_template_string",)),
    _Pattern("python.requests_user_input", "requests 请求 URL 可能来自用户输入，注意 SSRF 风险", "Medium", "CWE-918",
             function_names=("requests.get", "requests.post", "requests.request")),
]


class AstAnalyzer:
    """基于 AST 的 Python 代码分析器。"""

    name = "ast"

    def __init__(self, patterns: Optional[List[_Pattern]] = None) -> None:
        self.patterns = patterns or PATTERNS

    @classmethod
    def available(cls) -> bool:
        """AST 分析使用标准库，始终可用。"""
        return True

    def scan(self, files: List[Path], project_root: Path) -> List[ScanFinding]:
        findings: List[ScanFinding] = []
        for file_path in files:
            if file_path.suffix.lower() != ".py":
                continue
            try:
                source = file_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                try:
                    source = file_path.read_text(encoding="gbk")
                except (OSError, UnicodeDecodeError):
                    logger.debug("跳过无法读取的文件: %s", file_path)
                    continue
            findings.extend(self._analyze_source(source, file_path, project_root))
        return findings

    def _analyze_source(
        self, source: str, file_path: Path, project_root: Path
    ) -> List[ScanFinding]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []  # 非 Python 语法错误不处理

        rel = _relative(file_path, project_root)
        findings: List[ScanFinding] = []
        for node in ast.walk(tree):
            # 函数调用匹配
            if isinstance(node, ast.Call):
                finding = self._match_call(node, rel)
                if finding:
                    finding.code_snippet = _extract_snippet(source, node.lineno)
                    findings.append(finding)
        return findings

    def _match_call(self, node: ast.Call, rel_path: str) -> Optional[ScanFinding]:
        func = node.func
        name = _call_name(func)
        if not name:
            return None

        for pattern in self.patterns:
            if pattern.function_names and name in pattern.function_names:
                if pattern.require_shell_keyword and not _has_keyword(node, "shell"):
                    continue
                return ScanFinding(
                    scanner=self.name,
                    rule_id=pattern.rule_id,
                    severity=pattern.severity,
                    confidence="Medium",
                    message=pattern.message,
                    file_path=rel_path,
                    line=getattr(node, "lineno", 0),
                    cwe_id=pattern.cwe_id,
                )
            if pattern.attr_names and _is_attr_call(func, pattern.attr_names):
                # SQL 拼接：execute 参数中带 + / f-string / %
                if pattern.rule_id == "python.sql_concat" and not _sql_concat(node):
                    continue
                return ScanFinding(
                    scanner=self.name,
                    rule_id=pattern.rule_id,
                    severity=pattern.severity,
                    confidence="Medium",
                    message=pattern.message,
                    file_path=rel_path,
                    line=getattr(node, "lineno", 0),
                    cwe_id=pattern.cwe_id,
                )
        return None


# ---------- 辅助 ----------
def _call_name(func: ast.AST) -> str:
    """解析调用名：os.system -> os.system；eval -> eval。"""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: List[str] = []
        node = func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            parts.append(f"{node.func.id}()")
        return ".".join(reversed(parts))
    return ""


def _is_attr_call(func: ast.AST, attrs: tuple[str, ...]) -> bool:
    """判断是否为指定属性方法的调用（如 conn.execute）。"""
    return isinstance(func, ast.Attribute) and func.attr in attrs


def _has_keyword(node: ast.Call, name: str) -> bool:
    """检查关键字参数（如 shell=True）。"""
    for kw in node.keywords:
        if kw.arg == name:
            return True
    return False


def _sql_concat(node: ast.Call) -> bool:
    """判断 SQL 调用参数是否存在拼接特征。"""
    if not node.args:
        return False
    first = node.args[0]
    # f-string / 字符串 + 拼接 / % 格式化
    if isinstance(first, ast.JoinedStr):
        return True
    if isinstance(first, ast.BinOp) and isinstance(first.op, (ast.Add, ast.Mod)):
        return True
    return False


def _extract_snippet(source: str, lineno: int, radius: int = 1) -> str:
    """提取错误行附近的代码片段。"""
    lines = source.split("\n")
    start = max(0, lineno - 1 - radius)
    end = min(len(lines), lineno + radius)
    return "\n".join(lines[start:end])


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)
