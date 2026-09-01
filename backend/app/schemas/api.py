"""API Schemas（Pydantic 请求/响应模型）。"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------- 认证 ----------
class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=6, max_length=128)


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]


# ---------- 项目 ----------
class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = ""


class ProjectResponse(BaseModel):
    id: int
    name: str
    language: str
    description: str
    file_count: int
    created_at: Optional[str] = None


class UploadResponse(BaseModel):
    project_id: int
    name: str
    file_count: int
    language: str
    message: str


# ---------- 审计 ----------
class AuditCreate(BaseModel):
    project_id: int
    enable_knowledge: bool = True


class AuditStatusResponse(BaseModel):
    id: int
    task_id: str
    status: str
    language: str
    scanned_files: int
    total_findings: int
    security_score: int
    started_at: Optional[str] = None
    finished_at: Optional[str] = None


class VulnerabilityResponse(BaseModel):
    id: int
    file_path: str
    line: int
    vulnerability_type: str
    severity: str
    cwe_id: Optional[str] = None
    scanner: str
    rule_id: str
    confirmed: bool
    evidence: str
    reason: str


class RepairSuggestionResponse(BaseModel):
    id: int
    vulnerability_id: int
    root_cause: str
    principle: str
    suggestion: str
    fixed_code: str
    references: List[str] = []
    apply_to_source: bool


class AgentLogResponse(BaseModel):
    id: int
    agent_name: str
    input_summary: str
    output_summary: str
    status: str
    duration: float
    details: Dict[str, Any] = {}
    start_time: Optional[str] = None


class AuditResultResponse(BaseModel):
    task_id: str
    status: str
    duration: float
    report: Dict[str, Any]
    agent_chain: List[Dict[str, Any]]


# ---------- RAG ----------
class RagSearchRequest(BaseModel):
    query: str = Field(min_length=1)
    top_k: int = Field(default=5, ge=1, le=20)
    metadata_filter: Optional[Dict[str, Any]] = None
    rerank: Optional[bool] = None


class RagChunkResponse(BaseModel):
    page_content: str
    metadata: Dict[str, Any]
    score: float


# ---------- RAG 智能对话 ----------
class ChatSessionResponse(BaseModel):
    id: int
    title: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class ChatSessionCreate(BaseModel):
    title: str = "新会话"


class ChatMessageResponse(BaseModel):
    id: int
    session_id: int
    role: str
    content: str
    created_at: Optional[str] = None


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    session_id: Optional[int] = None
    top_k: int = Field(default=5, ge=1, le=20)


# ---------- 通用 ----------
class MessageResponse(BaseModel):
    message: str
