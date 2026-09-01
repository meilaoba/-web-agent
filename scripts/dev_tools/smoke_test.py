"""部署冒烟测试：对运行中的后端服务执行核心链路验证。

用法：
    1. 启动后端：scripts\launch\run_backend.cmd
    2. 运行：python scripts/dev_tools/smoke_test.py [--base-url http://127.0.0.1:8000]

验证项：
- 健康检查 / API 文档
- 注册 / 登录
- 创建项目 + 上传 zip + 审计 + 漏洞/报告查询
- RAG 检索
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import zipfile

import httpx

BASE = "http://127.0.0.1:8000"


def make_vuln_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "app/app.py",
            "import subprocess\n"
            "def run(cmd):\n"
            "    return subprocess.run(f'ping {cmd}', shell=True)\n"
            "import sqlite3\n"
            "def q(uid):\n"
            "    c = sqlite3.connect('a.db')\n"
            "    return c.execute('SELECT * FROM users WHERE id=' + uid)\n",
        )
    return buf.getvalue()


def check(name: str, ok: bool, detail: str = "") -> None:
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f" - {detail}" if detail and not ok else ""))
    if not ok:
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="后端冒烟测试")
    parser.add_argument("--base-url", default=BASE)
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    client = httpx.Client(base_url=base, timeout=180)

    # 1. 健康检查
    r = client.get("/api/health")
    check("健康检查", r.status_code == 200 and r.json().get("status") == "ok", r.text)

    # 2. 注册/登录
    import uuid

    uname = f"smoke_{uuid.uuid4().hex[:8]}"
    r = client.post("/api/auth/register", json={"username": uname, "password": "secret123"})
    check("注册", r.status_code == 200, r.text)
    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. 创建项目 + 上传
    r = client.post("/api/projects", json={"name": "smoke-demo"}, headers=headers)
    check("创建项目", r.status_code == 201, r.text)
    project_id = r.json()["id"]

    r = client.post(
        f"/api/projects/{project_id}/upload",
        files={"file": ("demo.zip", make_vuln_zip(), "application/zip")},
        headers=headers,
    )
    check("上传项目", r.status_code == 200, r.text)
    assert r.json()["language"] == "python"

    # 4. 执行审计
    r = client.post("/api/audit/tasks", json={"project_id": project_id}, headers=headers)
    check("执行审计", r.status_code == 201, r.text)
    task = r.json()
    check("审计完成且发现漏洞", task["status"] == "completed" and task["total_findings"] >= 1, json.dumps(task, ensure_ascii=False))
    task_id = task["id"]

    # 5. 漏洞 + 修复建议
    r = client.get(f"/api/vulnerabilities?task_id={task_id}", headers=headers)
    check("漏洞列表", r.status_code == 200 and len(r.json()) >= 1, r.text)
    vuln_id = r.json()[0]["id"]
    r = client.get(f"/api/vulnerabilities/{vuln_id}/suggestions", headers=headers)
    check("修复建议", r.status_code == 200 and len(r.json()) >= 1, r.text)

    # 6. Agent 执行链
    r = client.get(f"/api/agents/tasks/{task_id}/logs", headers=headers)
    check("Agent 执行链", r.status_code == 200 and len(r.json()) >= 4, r.text)

    # 7. 报告
    r = client.get(f"/api/reports/tasks/{task_id}", headers=headers)
    check("JSON 报告", r.status_code == 200 and "security_score" in r.json()["summary"], r.text)
    r = client.get(f"/api/reports/tasks/{task_id}?fmt=markdown", headers=headers)
    check("Markdown 报告", r.status_code == 200 and "安全审计报告" in r.text, r.text[:80])

    # 8. RAG 检索
    r = client.post("/api/rag/search", json={"query": "SQL 注入", "top_k": 3}, headers=headers)
    check("RAG 检索", r.status_code == 200, r.text)

    print("\n全部冒烟测试通过")


if __name__ == "__main__":
    main()
