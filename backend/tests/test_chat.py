"""RAG 智能对话 + 登录安全测试。"""

from __future__ import annotations

import pytest

from app.config import settings


def _register_login(client, username):
    r = client.post("/api/auth/register", json={"username": username, "password": "secret123"})
    if r.status_code != 200:
        r = client.post("/api/auth/login", json={"username": username, "password": "secret123"})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _parse_sse(body: str):
    """解析 SSE 响应体为事件列表。"""
    import json

    events = []
    for block in body.split("\n\n"):
        block = block.strip()
        if not block:
            continue
        etype, data = None, ""
        for line in block.split("\n"):
            if line.startswith("event:"):
                etype = line[6:].strip()
            elif line.startswith("data:"):
                data += line[5:].strip()
        if etype and data:
            try:
                events.append((etype, json.loads(data)))
            except json.JSONDecodeError:
                events.append((etype, data))
    return events


class TestLoginSecurity:
    def test_login_success(self, client):
        _register_login(client, "sec_user")

    def test_wrong_password(self, client):
        client.post("/api/auth/register", json={"username": "sec_user2", "password": "secret123"})
        r = client.post("/api/auth/login", json={"username": "sec_user2", "password": "wrongpass"})
        assert r.status_code == 401

    def test_lock_after_failures(self, client):
        """连续失败达到阈值后账号锁定（423）。"""
        username = "lock_user"
        client.post("/api/auth/register", json={"username": username, "password": "secret123"})
        max_attempts = settings.login_max_attempts
        locked = False
        for _ in range(max_attempts + 2):
            r = client.post("/api/auth/login", json={"username": username, "password": "badpass"})
            if r.status_code == 423:
                locked = True
                break
        assert locked, "达到失败阈值后应返回 423 锁定"
        # 即使密码正确也应被锁定
        r = client.post("/api/auth/login", json={"username": username, "password": "secret123"})
        assert r.status_code == 423


class TestChatSessions:
    def test_session_crud(self, client):
        headers = _register_login(client, "chat_user")
        # 新建
        r = client.post("/api/rag/sessions", json={"title": "测试会话"}, headers=headers)
        assert r.status_code == 201
        sid = r.json()["id"]
        # 列表
        r = client.get("/api/rag/sessions", headers=headers)
        assert r.status_code == 200
        assert any(s["id"] == sid for s in r.json())
        # 消息（初始为空）
        r = client.get(f"/api/rag/sessions/{sid}/messages", headers=headers)
        assert r.status_code == 200 and r.json() == []
        # 删除
        r = client.delete(f"/api/rag/sessions/{sid}", headers=headers)
        assert r.status_code == 204
        r = client.get(f"/api/rag/sessions/{sid}/messages", headers=headers)
        assert r.status_code == 404

    def test_session_isolation(self, client):
        """不同用户的会话互相隔离。"""
        h1 = _register_login(client, "iso_user1")
        h2 = _register_login(client, "iso_user2")
        r = client.post("/api/rag/sessions", json={"title": "user1 会话"}, headers=h1)
        sid = r.json()["id"]
        # user2 无法访问 user1 的会话
        r = client.get(f"/api/rag/sessions/{sid}/messages", headers=h2)
        assert r.status_code == 404


class TestChatStream:
    def test_chat_flow(self, client):
        """完整对话流：status -> sources -> token -> done。"""
        headers = _register_login(client, "chatflow_user")
        r = client.post(
            "/api/rag/chat",
            json={"message": "什么是SQL注入", "top_k": 3},
            headers=headers,
        )
        assert r.status_code == 200
        assert "text/event-stream" in r.headers.get("content-type", "")
        events = _parse_sse(r.text)
        types = [e[0] for e in events]
        # 应包含状态、来源、token、done
        assert "status" in types
        assert "sources" in types
        assert "token" in types
        assert "done" in types
        # token 内容非空
        tokens = "".join(e[1] if isinstance(e[1], str) else "" for e in events if e[0] == "token")
        assert tokens.strip(), "流式回答不应为空"
        # sources 有内容
        src_events = [e for e in events if e[0] == "sources"]
        assert src_events and isinstance(src_events[0][1], list)

    def test_chat_saves_history(self, client):
        """对话后消息入库，可恢复。"""
        headers = _register_login(client, "hist_user")
        r = client.post(
            "/api/rag/chat", json={"message": "什么是SSRF", "top_k": 2}, headers=headers
        )
        events = _parse_sse(r.text)
        done = [e for e in events if e[0] == "done"]
        assert done
        sid = done[0][1]["session_id"]
        # 历史消息应包含 user 与 assistant
        r = client.get(f"/api/rag/sessions/{sid}/messages", headers=headers)
        msgs = r.json()
        roles = [m["role"] for m in msgs]
        assert "user" in roles and "assistant" in roles

    def test_chat_context_memory(self, client):
        """第二轮对话应携带历史（通过 MockLLM 规则无法直接验证，但流程不应报错）。"""
        headers = _register_login(client, "mem_user")
        r1 = client.post(
            "/api/rag/chat", json={"message": "SQL注入是什么", "top_k": 2}, headers=headers
        )
        done1 = [e for e in _parse_sse(r1.text) if e[0] == "done"]
        sid = done1[0][1]["session_id"]
        # 同会话第二轮
        r2 = client.post(
            "/api/rag/chat",
            json={"message": "那Java应该怎么修复", "session_id": sid, "top_k": 2},
            headers=headers,
        )
        assert r2.status_code == 200
        events2 = _parse_sse(r2.text)
        assert any(e[0] == "token" for e in events2)
        assert any(e[0] == "done" for e in events2)

    def test_chat_empty_knowledge_no_crash(self, client):
        """知识库为空时对话仍应正常（MockLLM 兜底回答）。"""
        headers = _register_login(client, "empty_user")
        r = client.post(
            "/api/rag/chat", json={"message": "随便问问", "top_k": 3}, headers=headers
        )
        assert r.status_code == 200
        events = _parse_sse(r.text)
        assert any(e[0] in ("token", "error") for e in events)


class TestChatClassification:
    """问题分类：普通问题不触发 RAG，安全问题触发 RAG。"""

    def _chat(self, client, headers, message, session_id=None):
        r = client.post(
            "/api/rag/chat",
            json={"message": message, "session_id": session_id, "top_k": 3},
            headers=headers,
        )
        assert r.status_code == 200
        return _parse_sse(r.text)

    def test_general_question_no_rag(self, client):
        """普通问题：meta.used_rag=false，无 sources 事件，无"已找到"状态。"""
        headers = _register_login(client, "cls_general")
        for q in ("你好", "你是谁？", "你能做什么？", "谢谢"):
            events = self._chat(client, headers, q)
            meta = next((e[1] for e in events if e[0] == "meta"), None)
            assert meta is not None and meta.get("used_rag") is False, f"{q} 不应触发 RAG"
            assert not any(e[0] == "sources" for e in events), f"{q} 不应返回 sources"
            assert not any(
                e[0] == "status" and "已找到" in str(e[1]) for e in events
            ), f"{q} 不应显示检索数量"
            assert any(e[0] == "token" for e in events), f"{q} 应正常回答"

    def test_security_question_uses_rag(self, client):
        """安全问题：meta.used_rag=true，有 sources 事件与检索状态。"""
        headers = _register_login(client, "cls_sec")
        for q in ("什么是SQL注入？", "如何修复XSS？", "分析这段代码是否存在漏洞？"):
            events = self._chat(client, headers, q)
            meta = next((e[1] for e in events if e[0] == "meta"), None)
            assert meta is not None and meta.get("used_rag") is True, f"{q} 应触发 RAG"
            assert any(e[0] == "sources" for e in events), f"{q} 应返回参考知识"
            assert any(e[0] == "status" and "已找到" in str(e[1]) for e in events), f"{q} 应显示检索数量"
            assert any(e[0] == "token" for e in events), f"{q} 应正常回答"

    def test_context_inheritance(self, client):
        """对话上下文：承接安全问题的"那怎么修复？"应触发 RAG。"""
        headers = _register_login(client, "cls_ctx")
        events = self._chat(client, headers, "Java中的SQL注入怎么修复")
        done = next(e[1] for e in events if e[0] == "done")
        sid = done["session_id"]
        # 第二轮承接问题
        events2 = self._chat(client, headers, "那应该怎么修复？", session_id=sid)
        meta = next((e[1] for e in events2 if e[0] == "meta"), None)
        assert meta is not None and meta.get("used_rag") is True, "承接安全话题应触发 RAG"
