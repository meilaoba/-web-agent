"""后端 API 集成测试（FastAPI TestClient + 独立 SQLite）。"""

from __future__ import annotations

import io
import zipfile

import pytest


def make_vuln_zip() -> bytes:
    """构造含漏洞的 Python 项目 zip。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "vulnapp/app.py",
            "import subprocess\n"
            "import sqlite3\n"
            "def run(x):\n"
            "    return subprocess.run(f'ping {x}', shell=True)\n"
            "def query(uid):\n"
            "    conn = sqlite3.connect('app.db')\n"
            "    return conn.execute('SELECT * FROM users WHERE id=' + uid)\n",
        )
        zf.writestr("vulnapp/README.md", "# vulnapp demo\n")
    return buf.getvalue()


@pytest.fixture(scope="module")
def auth_headers(client):
    """注册 + 登录，返回认证头。"""
    username = "tester"
    client.post(
        "/api/auth/register",
        json={"username": username, "password": "secret123"},
    )
    resp = client.post(
        "/api/auth/login", json={"username": username, "password": "secret123"}
    )
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def uploaded_project(client, auth_headers):
    """创建项目并上传漏洞 zip。"""
    resp = client.post(
        "/api/projects", json={"name": "vulnapp", "description": "测试项目"},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = client.post(
        f"/api/projects/{project_id}/upload",
        files={"file": ("vulnapp.zip", make_vuln_zip(), "application/zip")},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["language"] == "python"
    assert data["file_count"] == 1
    return {"project_id": project_id, "auth_headers": auth_headers}


class TestAuth:
    def test_register_login(self, client):
        resp = client.post(
            "/api/auth/register", json={"username": "user2", "password": "pass123456"}
        )
        assert resp.status_code == 200
        assert resp.json()["access_token"]
        resp = client.post(
            "/api/auth/login", json={"username": "user2", "password": "wrongpass"}
        )
        assert resp.status_code == 401

    def test_protected_route_requires_token(self, client):
        resp = client.get("/api/projects")
        assert resp.status_code == 401


class TestProjects:
    def test_list_projects(self, client, auth_headers):
        resp = client.get("/api/projects", headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_upload_invalid_zip(self, client, auth_headers, uploaded_project):
        resp = client.post(
            f"/api/projects/{uploaded_project['project_id']}/upload",
            files={"file": ("bad.txt", b"not a zip", "text/plain")},
            headers=auth_headers,
        )
        assert resp.status_code == 400

    def test_upload_zip_slip_rejected(self, client, auth_headers, uploaded_project):
        """路径穿越 zip 应被拒绝。"""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../evil.py", "print('evil')")
        resp = client.post(
            f"/api/projects/{uploaded_project['project_id']}/upload",
            files={"file": ("evil.zip", buf.getvalue(), "application/zip")},
            headers=auth_headers,
        )
        assert resp.status_code == 400


class TestAuditFlow:
    def test_full_audit(self, client, uploaded_project):
        """完整链路：创建审计 -> 查询漏洞/建议/报告/Agent 日志。"""
        project_id = uploaded_project["project_id"]
        headers = uploaded_project["auth_headers"]

        # 1. 创建审计任务
        resp = client.post(
            "/api/audit/tasks", json={"project_id": project_id},
            headers=headers,
        )
        assert resp.status_code == 201
        task = resp.json()
        assert task["status"] == "completed"
        assert task["total_findings"] >= 1
        assert 0 <= task["security_score"] <= 100
        task_id = task["id"]

        # 2. 漏洞列表
        resp = client.get(f"/api/vulnerabilities?task_id={task_id}", headers=headers)
        assert resp.status_code == 200
        vulns = resp.json()
        assert len(vulns) >= 1
        first = vulns[0]
        assert first["file_path"]
        assert first["severity"] in ("Critical", "High", "Medium", "Low", "Info")

        # 3. 修复建议
        resp = client.get(
            f"/api/vulnerabilities/{first['id']}/suggestions", headers=headers
        )
        assert resp.status_code == 200
        suggestions = resp.json()
        assert len(suggestions) >= 1
        assert suggestions[0]["suggestion"]

        # 4. 审计结果（报告 + Agent 执行链）
        resp = client.get(f"/api/audit/tasks/{task_id}/result", headers=headers)
        assert resp.status_code == 200
        result = resp.json()
        assert result["report"]["summary"]["total_findings"] >= 1
        agents = {e["agent_name"] for e in result["agent_chain"]}
        assert {"orchestrator", "audit_agent", "repair_agent", "report_agent"} <= agents

        # 5. Agent 日志接口
        resp = client.get(f"/api/agents/tasks/{task_id}/logs", headers=headers)
        assert resp.status_code == 200
        assert len(resp.json()) == len(result["agent_chain"])

        # 6. 报告（JSON + Markdown）
        resp = client.get(f"/api/reports/tasks/{task_id}", headers=headers)
        assert resp.status_code == 200
        assert "security_score" in resp.json()["summary"]
        resp = client.get(f"/api/reports/tasks/{task_id}?fmt=markdown", headers=headers)
        assert resp.status_code == 200
        assert "# 安全审计报告" in resp.text

    def test_task_access_control(self, client, uploaded_project):
        """他人无法访问任务。"""
        # 注册另一个用户
        client.post(
            "/api/auth/register", json={"username": "other", "password": "secret123"}
        )
        login = client.post(
            "/api/auth/login", json={"username": "other", "password": "secret123"}
        )
        other_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        # 用第一个用户的项目创建一个任务
        project_id = uploaded_project["project_id"]
        headers = uploaded_project["auth_headers"]
        resp = client.post(
            "/api/audit/tasks", json={"project_id": project_id}, headers=headers
        )
        task_id = resp.json()["id"]

        resp = client.get(f"/api/audit/tasks/{task_id}", headers=other_headers)
        assert resp.status_code == 404


class TestRagApi:
    def test_rag_search(self, client, auth_headers):
        resp = client.post(
            "/api/rag/search",
            json={"query": "SQL 注入 如何修复", "top_k": 3},
            headers=auth_headers,
        )
        # 知识库可能为空（未执行入库脚本），接口本身应可用
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_rag_stats(self, client, auth_headers):
        resp = client.get("/api/rag/stats", headers=auth_headers)
        assert resp.status_code == 200
        assert "chunk_count" in resp.json()
