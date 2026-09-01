"""RAG API：知识检索 + 智能对话（SSE 流式）。

对话流程：
    用户问题 → 会话记忆（DB） → RAG 检索 → Top-K 知识 → LLM 流式 → 保存历史
"""

from __future__ import annotations

import json
import logging
from typing import Any, AsyncIterator, Dict

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..models import User
from ..rag.retriever import get_default_retriever
from ..schemas.api import (
    ChatMessageResponse,
    ChatRequest,
    ChatSessionCreate,
    ChatSessionResponse,
    RagChunkResponse,
    RagSearchRequest,
)
from ..services.chat_service import ChatService
from .deps import get_current_user, get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/rag", tags=["RAG知识库"])


# ---------- 检索（保留原接口，兼容现有调用） ----------
@router.post("/search", response_model=list[RagChunkResponse])
def rag_search(
    body: RagSearchRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """知识库检索：查询安全知识（Top-K + Metadata 过滤 + 可选重排）。"""
    retriever = get_default_retriever(top_k=body.top_k)
    chunks = retriever.retrieve(
        body.query,
        top_k=body.top_k,
        metadata_filter=body.metadata_filter,
        rerank=body.rerank,
    )
    return [
        RagChunkResponse(
            page_content=c.page_content,
            metadata=c.metadata,
            score=c.score,
        )
        for c in chunks
    ]


@router.get("/stats")
def rag_stats(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """知识库统计（Chunk 数量 / 分类分布）。"""
    from ..config import settings
    from ..rag.vector_store import ChromaVectorStore

    store = ChromaVectorStore(settings.chroma_dir, settings.chroma_collection)
    return {
        "collection": settings.chroma_collection,
        "chunk_count": store.count(),
    }


# ---------- 会话管理 ----------
@router.get("/sessions", response_model=list[ChatSessionResponse])
def list_sessions(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """当前用户的会话列表（按更新时间倒序）。"""
    service = ChatService(db)
    return [s.to_dict() for s in service.list_sessions(user.id)]


@router.post("/sessions", response_model=ChatSessionResponse, status_code=status.HTTP_201_CREATED)
def create_session(
    body: ChatSessionCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """新建会话。"""
    service = ChatService(db)
    session = service.create_session(user.id, title=body.title)
    return session.to_dict()


@router.get("/sessions/{session_id}/messages", response_model=list[ChatMessageResponse])
def get_session_messages(
    session_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """获取会话历史消息（用于页面刷新后恢复）。"""
    service = ChatService(db)
    session = service.get_session(session_id, user.id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="会话不存在")
    return [m.to_dict() for m in service.get_messages(session_id)]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_session(
    session_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """删除会话及其消息。"""
    service = ChatService(db)
    session = service.get_session(session_id, user.id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="会话不存在")
    service.delete_session(session)


# ---------- 智能对话（SSE 流式） ----------
@router.post("/chat")
async def rag_chat(
    body: ChatRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """RAG 智能对话：检索知识 → LLM 流式回答（SSE）。

    事件格式（text/event-stream）：
        event: status   data: {"message": "正在检索知识库..."}
        event: sources  data: [{"title": "CWE-918", "document": "ssrf.md", ...}]
        event: token    data: "增量文本"
        event: done     data: {"session_id": 1}
        event: error    data: {"message": "..."}
    """
    service = ChatService(db)

    async def event_stream() -> AsyncIterator[str]:
        try:
            for event in service.chat_stream(
                user.id, body.message, session_id=body.session_id, top_k=body.top_k
            ):
                event_type = event["type"]
                if event_type == "token":
                    yield f"event: token\ndata: {json.dumps(event['content'], ensure_ascii=False)}\n\n"
                elif event_type == "sources":
                    yield f"event: sources\ndata: {json.dumps(event['sources'], ensure_ascii=False)}\n\n"
                elif event_type == "status":
                    yield f"event: status\ndata: {json.dumps({'message': event['message']}, ensure_ascii=False)}\n\n"
                elif event_type == "meta":
                    yield f"event: meta\ndata: {json.dumps({'used_rag': event['used_rag']})}\n\n"
                elif event_type == "done":
                    yield f"event: done\ndata: {json.dumps({'session_id': event['session_id']})}\n\n"
                elif event_type == "error":
                    yield f"event: error\ndata: {json.dumps({'message': event['message']}, ensure_ascii=False)}\n\n"
        except Exception as exc:  # 兜底：不向前端泄露内部异常
            logger.error("对话流异常: %s", exc)
            yield f"event: error\ndata: {json.dumps({'message': '服务内部错误，请稍后重试'}, ensure_ascii=False)}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
