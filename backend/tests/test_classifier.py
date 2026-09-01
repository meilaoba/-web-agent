"""问题意图分类器测试：安全 vs 普通问题。"""

from __future__ import annotations

import pytest

from app.rag.query_classifier import classify_security_query


class TestSecurityQueries:
    """应触发 RAG 的安全问题。"""

    @pytest.mark.parametrize(
        "query",
        [
            "什么是SQL注入？",
            "如何修复Java中的SQL注入？",
            "这段代码是否存在XSS？",
            "SSRF漏洞怎么检测？",
            "CWE-78是什么？",
            "如何防止命令注入？",
            "分析这段代码的安全风险",
            "如何修复这个漏洞？",
            "Java代码中的SQL注入如何修复？",
            "什么是跨站脚本攻击？",
            "服务器如何防护CSRF？",
            "XXE 注入怎么防御？",
            "反序列化漏洞原理",
            "这个接口有越权风险吗？",
            "如何检测路径遍历攻击？",
            "文件上传漏洞怎么修复？",
            "OWASP Top 10 有哪些？",
        ],
    )
    def test_security(self, query):
        assert classify_security_query(query) is True, f"应判定为安全问题: {query}"


class TestGeneralQueries:
    """不应触发 RAG 的普通问题。"""

    @pytest.mark.parametrize(
        "query",
        [
            "你好",
            "你是谁？",
            "你能做什么？",
            "谢谢",
            "现在几点？",
            "帮我解释一下人工智能",
            "什么是Python？",
            "今天天气怎么样",
            "讲个笑话",
            "再见",
        ],
    )
    def test_general(self, query):
        assert classify_security_query(query) is False, f"应判定为普通问题: {query}"


class TestEdgeCases:
    def test_greeting_plus_security(self):
        """问候语 + 安全词 → 安全问题（安全词优先）。"""
        assert classify_security_query("你好，请问什么是SQL注入？") is True

    def test_code_analysis(self):
        """含代码分析词 → 安全问题。"""
        assert classify_security_query("帮我看看这段代码") is True

    def test_context_inheritance(self):
        """无明确信号但上一条是安全问题 → 继承为安全（如"那怎么修复？"）。"""
        assert classify_security_query("那应该怎么修复？", last_user_message="Java中的SQL注入怎么修复") is True

    def test_greeting_ignores_context(self):
        """明确闲聊词即使承接安全话题也是普通问题。"""
        assert classify_security_query("谢谢", last_user_message="什么是SQL注入") is False

    def test_empty_query(self):
        assert classify_security_query("") is False
