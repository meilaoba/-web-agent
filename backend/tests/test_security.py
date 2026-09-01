"""安全分析模块测试：项目解析 / AST 分析 / 漏洞检测。"""

from __future__ import annotations

import zipfile

import pytest

from app.security.ast_analyzer import AstAnalyzer
from app.security.detector import VulnerabilityDetector
from app.security.project_parser import ProjectParseError, ProjectParser

#: 含多种漏洞的 Python 样例
VULNERABLE_PY = '''\
import os
import subprocess
import pickle

def run_cmd(user_input):
    # 命令注入：shell 拼接
    result = subprocess.run(f"ping -c 3 {user_input}", shell=True)
    return result

def unsafe_sql(user_input):
    import sqlite3
    conn = sqlite3.connect("app.db")
    # SQL 注入：字符串拼接
    cur = conn.execute("SELECT * FROM users WHERE id=" + user_input)
    return cur

def unsafe_pickle(data):
    # 不安全反序列化
    obj = pickle.loads(data)
    return obj

def eval_code(code):
    # 动态执行
    eval(code)

def safe_code():
    # 安全示例：参数化查询
    import sqlite3
    conn = sqlite3.connect("app.db")
    cur = conn.execute("SELECT * FROM users WHERE id=?", (1,))
    return cur
'''


@pytest.fixture()
def vuln_project(tmp_path):
    """含漏洞样例的项目目录。"""
    (tmp_path / "vuln.py").write_text(VULNERABLE_PY, encoding="utf-8")
    (tmp_path / "README.md").write_text("# demo", encoding="utf-8")
    return tmp_path


class TestProjectParser:
    def test_extract_zip_normal(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text("print(1)", encoding="utf-8")
        zip_path = tmp_path / "proj.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.write(src / "app.py", "proj/app.py")
        parser = ProjectParser(tmp_path / "work")
        target = parser.extract_zip(zip_path, "proj")
        assert (target / "app.py").is_file()

    def test_extract_zip_slip_raises(self, tmp_path):
        """Zip Slip（.. 逃逸）应被拒绝。"""
        zip_path = tmp_path / "evil.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../evil.py", "print('evil')")
        parser = ProjectParser(tmp_path / "work")
        with pytest.raises(ProjectParseError):
            parser.extract_zip(zip_path, "proj")

    def test_collect_and_detect_language(self, tmp_path):
        (tmp_path / "a.py").write_text("x=1", encoding="utf-8")
        (tmp_path / "b.java").write_text("class A{}", encoding="utf-8")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "c.py").write_text("x=2", encoding="utf-8")
        parser = ProjectParser(tmp_path)
        files = parser.collect_source_files(tmp_path)
        names = {f.name for f in files}
        assert "a.py" in names and "b.java" in names
        assert "c.py" not in names  # 依赖目录被跳过
        assert parser.detect_language(files) == "python"

    def test_bad_zip_raises(self, tmp_path):
        bad = tmp_path / "bad.zip"
        bad.write_bytes(b"not a zip")
        parser = ProjectParser(tmp_path / "work")
        with pytest.raises(ProjectParseError):
            parser.extract_zip(bad, "proj")


class TestAstAnalyzer:
    def test_detect_vulnerable_patterns(self, vuln_project):
        files = [vuln_project / "vuln.py"]
        findings = AstAnalyzer().scan(files, vuln_project)
        rule_ids = {f.rule_id for f in findings}
        assert "python.subprocess_shell" in rule_ids
        assert "python.sql_concat" in rule_ids
        assert "python.pickle_loads" in rule_ids
        assert "python.eval" in rule_ids

    def test_severity_and_cwe(self, vuln_project):
        findings = AstAnalyzer().scan([vuln_project / "vuln.py"], vuln_project)
        for f in findings:
            assert f.severity in ("Critical", "High", "Medium", "Low", "Info")
        sql = next(f for f in findings if f.rule_id == "python.sql_concat")
        assert sql.cwe_id == "CWE-89"
        assert sql.line > 0
        assert "execute" in sql.code_snippet


class TestVulnerabilityDetector:
    def test_scan_project(self, vuln_project):
        detector = VulnerabilityDetector()
        result = detector.scan_project(vuln_project, "demo")
        assert result.scanned_files == 1
        assert result.language == "python"
        assert result.findings, "应至少发现漏洞"
        assert "ast" in result.scanner_status
        assert result.severity_counts().get("High", 0) >= 1

    def test_dedupe(self, vuln_project):
        detector = VulnerabilityDetector()
        result1 = detector.scan_project(vuln_project, "demo")
        result2 = detector.scan_project(vuln_project, "demo")
        # 两次扫描的 AST 发现应一致且无重复
        assert len(result1.findings) == len(result2.findings)
