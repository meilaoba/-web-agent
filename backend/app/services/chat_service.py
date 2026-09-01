"""RAG 对话服务：会话记忆 + 问题分类 + RAG 检索 + LLM 流式回答。

对话流程：
    用户问题 → 问题分类（安全/普通）
      ├─ 安全问题：会话记忆 → RAG 检索 → Top-K 知识 → LLM（流式）→ 参考知识
      └─ 普通问题：直接 LLM（流式），不检索、不显示参考知识
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional

from sqlalchemy.orm import Session

from ..agents.llm import LLMClient, get_llm_client
from ..models.chat import ChatMessage, ChatSession
from ..rag.query_classifier import classify_security_query
from ..rag.retriever import Retriever, get_default_retriever
from ..rag.vector_store import RetrievedChunk

logger = logging.getLogger(__name__)

#: 会话记忆窗口：携带的历史消息条数（最近 N 条）
HISTORY_WINDOW = 6

#: 系统提示：安全问题（带参考知识）
_SYSTEM_PROMPT = (
    "你是 Web 代码安全审计助手。请基于提供的安全知识（参考知识）回答用户问题，"
    "回答要点：漏洞成因、检测方法、修复建议。可引用 CWE / OWASP 编号。"
    "若参考知识不足以回答，请如实说明并给出通用安全建议。"
)

#: 系统提示：普通问题（无参考知识）
_GENERAL_SYSTEM_PROMPT = (
    "你是 Web 代码安全审计助手。请简洁友好地回答用户的普通问题；"
    "若问题与 Web 安全、代码安全无关，按通用知识正常回答即可。"
)


class ChatServiceError(Exception):
    """对话服务异常。"""


class ChatService:
    """RAG 智能对话服务。"""

    def __init__(
        self,
        db: Session,
        retriever: Optional[Retriever] = None,
        llm: Optional[LLMClient] = None,
    ) -> None:
        self.db = db
        self._retriever = retriever
        self._llm = llm

    @property
    def retriever(self) -> Retriever:
        if self._retriever is None:
            self._retriever = get_default_retriever()
        return self._retriever

    @property
    def llm(self) -> LLMClient:
        if self._llm is None:
            self._llm = get_llm_client()
        return self._llm

    # ---------- 会话管理 ----------
    def create_session(self, user_id: int, title: str = "新会话") -> ChatSession:
        session = ChatSession(user_id=user_id, title=title[:128] or "新会话")
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return session

    def list_sessions(self, user_id: int) -> List[ChatSession]:
        return (
            self.db.query(ChatSession)
            .filter(ChatSession.user_id == user_id)
            .order_by(ChatSession.updated_at.desc())
            .all()
        )

    def get_session(self, session_id: int, user_id: int) -> Optional[ChatSession]:
        return (
            self.db.query(ChatSession)
            .filter(ChatSession.id == session_id, ChatSession.user_id == user_id)
            .first()
        )

    def delete_session(self, session: ChatSession) -> None:
        self.db.query(ChatMessage).filter(ChatMessage.session_id == session.id).delete()
        self.db.delete(session)
        self.db.commit()

    def get_messages(self, session_id: int, limit: int = 200) -> List[ChatMessage]:
        return (
            self.db.query(ChatMessage)
            .filter(ChatMessage.session_id == session_id)
            .order_by(ChatMessage.id.asc())
            .limit(limit)
            .all()
        )

    def _add_message(self, session_id: int, role: str, content: str) -> ChatMessage:
        msg = ChatMessage(session_id=session_id, role=role, content=content)
        self.db.add(msg)
        self.db.commit()
        self.db.refresh(msg)
        return msg

    def _last_user_message(self, session_id: int) -> Optional[str]:
        """获取当前问题之前最近一条用户消息（用于对话上下文分类继承）。"""
        msg = (
            self.db.query(ChatMessage)
            .filter(ChatMessage.session_id == session_id, ChatMessage.role == "user")
            .order_by(ChatMessage.id.desc())
            .offset(1)  # 跳过刚保存的当前消息
            .first()
        )
        return msg.content if msg else None

    # ---------- 对话执行 ----------
    def chat_stream(
        self,
        user_id: int,
        message: str,
        session_id: Optional[int] = None,
        top_k: int = 5,
    ) -> Iterator[Dict[str, Any]]:
        """执行一轮对话，流式产出事件。

        问题分类：先判断是否为 Web 安全 / 代码安全问题——
        - 安全问题：执行 RAG 检索，返回 sources（参考知识），LLM 回答携带知识；
        - 普通问题：直接调用 LLM，不检索、不返回 sources。

        Yields:
            {"type": "meta", "used_rag": bool}  是否使用 RAG（前端据此显示参考知识）
            {"type": "status", "message": str}  检索/生成状态
            {"type": "sources", "sources": list} 参考知识来源（仅安全问题时）
            {"type": "token", "content": str}   增量文本
            {"type": "done", "session_id": int}  完成
            {"type": "error", "message": str}    失败（不泄露内部异常）
        """
        # 1. 会话：取或建
        session = None
        if session_id:
            session = self.get_session(session_id, user_id)
            if session is None:
                yield {"type": "error", "message": "会话不存在或无权访问"}
                return
        if session is None:
            session = self.create_session(user_id, title=_make_title(message))
        session_id = session.id

        # 2. 保存用户消息
        self._add_message(session_id, "user", message)

        # 3. 问题分类（是否安全问题）
        last_user = self._last_user_message(session_id)
        used_rag = classify_security_query(message, last_user_message=last_user)
        yield {"type": "meta", "used_rag": used_rag}

        chunks: List[RetrievedChunk] = []
        if used_rag:
            # 4a. 安全问题：RAG 检索
            yield {"type": "status", "message": "正在检索知识库..."}
            try:
                chunks = self.retriever.retrieve(message, top_k=top_k)
            except Exception as exc:
                logger.warning("RAG 检索失败: %s", exc)
                chunks = []
            yield {"type": "status", "message": f"已找到 {len(chunks)} 条相关知识"}
            # 参考知识（供前端展示来源）
            yield {"type": "sources", "sources": [_chunk_source(c) for c in chunks]}
        else:
            # 4b. 普通问题：直接 LLM，不检索、不返回 sources
            logger.debug("普通问题（不触发 RAG）: %s", message[:50])

        # 5. 构造 Prompt（会话记忆 + 可选 RAG 知识）
        messages = self._build_messages(session_id, message, chunks)

        # 6. LLM 流式生成
        yield {"type": "status", "message": "正在生成回答..."}
        collected: List[str] = []
        try:
            for token in self.llm.chat_stream(messages):
                collected.append(token)
                yield {"type": "token", "content": token}
        except Exception as exc:
            logger.warning("LLM 流式生成失败: %s", exc)
            yield {"type": "error", "message": "模型服务暂不可用，请稍后重试或检查模型配置"}
            # 保存部分回答（如有）
            if collected:
                self._add_message(session_id, "assistant", "".join(collected))
            self.db.query(ChatSession).filter(ChatSession.id == session_id).update(
                {"updated_at": datetime.now()}
            )
            self.db.commit()
            return

        answer = "".join(collected)
        if answer.strip():
            self._add_message(session_id, "assistant", answer)
        else:
            yield {"type": "error", "message": "模型返回为空，请重试"}

        # 更新会话标题（首轮用问题前 20 字）
        first_msg = self.db.query(ChatMessage).filter(ChatMessage.session_id == session_id).first()
        if first_msg and first_msg.content == message:
            self.db.query(ChatSession).filter(ChatSession.id == session_id).update(
                {"title": _make_title(message), "updated_at": datetime.now()}
            )
        else:
            self.db.query(ChatSession).filter(ChatSession.id == session_id).update(
                {"updated_at": datetime.now()}
            )
        self.db.commit()
        yield {"type": "done", "session_id": session_id}

    # ---------- Prompt 构造 ----------
    def _build_messages(
        self, session_id: int, user_message: str, chunks: List[RetrievedChunk]
    ) -> List[Dict[str, str]]:
        """构造 OpenAI 格式消息：System(助手+可选知识) + 历史 + User。

        chunks 非空（安全问题的 RAG 检索结果）时，System 提示携带参考知识；
        chunks 为空（普通问题）时使用普通系统提示，不携带知识段。
        """
        if chunks:
            system = _SYSTEM_PROMPT
            knowledge = _format_knowledge(chunks)
            if knowledge:
                system += f"\n\n【参考知识】\n{knowledge}"
        else:
            system = _GENERAL_SYSTEM_PROMPT
        messages: List[Dict[str, str]] = [{"role": "system", "content": system}]

        # 会话记忆：最近 HISTORY_WINDOW 条历史（排除当前问题，避免重复）
        history = self.get_messages(session_id, limit=HISTORY_WINDOW + 1)
        for msg in history[:-1]:  # 最后一条是刚保存的当前问题
            messages.append({"role": "assistant" if msg.role == "assistant" else "user", "content": msg.content})

        messages.append({"role": "user", "content": user_message})
        return messages


def _format_knowledge(chunks: List[RetrievedChunk], max_chars: int = 3000) -> str:
    """将检索结果格式化为供 LLM 使用的知识文本（含来源标记）。"""
    if not chunks:
        return "（知识库无相关命中）"
    parts: List[str] = []
    budget = max_chars
    for i, c in enumerate(chunks, 1):
        meta = c.metadata
        header = (
            f"[{i}] 来源={meta.get('document_name', '?')} "
            f"CWE={meta.get('cwe_id', '?')} 分类={meta.get('category', '?')}"
        )
        body = c.page_content[: max(200, budget // max(1, len(chunks)))]
        budget -= len(body)
        parts.append(f"{header}\n{body}")
        if budget <= 0:
            break
    return "\n\n".join(parts)


def _chunk_source(c: RetrievedChunk) -> Dict[str, Any]:
    """构造前端展示的知识来源。"""
    meta = c.metadata
    return {
        "title": meta.get("cwe_id") or meta.get("cnnvd_id") or meta.get("title") or meta.get("document_name", "?"),
        "document": meta.get("document_name", "?"),
        "category": meta.get("category", "?"),
        "score": round(c.score, 3),
        "preview": c.page_content[:120],
    }


def _make_title(message: str) -> str:
    """从首条消息生成会话标题。"""
    cleaned = re.sub(r"\s+", " ", message).strip()
    return cleaned[:20] if cleaned else "新会话"
