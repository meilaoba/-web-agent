"""FastAPI 应用入口。

启动：
    cd backend
    python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import (
    agents_router,
    audit_router,
    auth_router,
    projects_router,
    rag_router,
    reports_router,
    vulnerabilities_router,
)
from .config import settings, setup_logging
from .services.db import init_db

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期：启动时初始化数据库并做安全配置检查。"""
    setup_logging()
    init_db()
    _warn_insecure_config()
    logger.info("应用启动：数据库已初始化")
    yield


def _warn_insecure_config() -> None:
    """启动时安全配置检查：生产模式（MySQL）下使用默认 JWT_SECRET 时告警。"""
    default_secrets = {"dev-secret-do-not-use-in-production", "change-me-in-production"}
    if settings.db_type == "mysql" and settings.jwt_secret in default_secrets:
        logger.warning(
            "检测到生产模式(DB_TYPE=mysql)仍使用默认 JWT_SECRET，"
            "存在严重安全风险，请立即在 .env 中设置强随机密钥"
            "(可用: python -c 'import secrets; print(secrets.token_hex(32))')"
        )


app = FastAPI(
    title="AI驱动的Web代码安全审计多Agent系统",
    description="AI-Driven Multi-Agent Web Code Security Audit System",
    version="0.2.0",
    lifespan=lifespan,
)

# CORS：默认放开所有来源（开发环境）；生产部署请通过 CORS_ORIGINS 配置白名单
_cors_origins_raw = settings.cors_origins.strip()
_cors_origins = (
    [o.strip() for o in _cors_origins_raw.split(",") if o.strip()]
    if _cors_origins_raw
    else ["*"]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    # 通配来源不允许携带凭据（浏览器规范）；系统使用 JWT 头认证，不依赖 Cookie
    allow_credentials=(_cors_origins != ["*"]),
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
app.include_router(auth_router)
app.include_router(projects_router)
app.include_router(audit_router)
app.include_router(vulnerabilities_router)
app.include_router(rag_router)
app.include_router(agents_router)
app.include_router(reports_router)


@app.get("/")
def root():
    return {
        "name": "AI驱动的Web代码安全审计多Agent系统",
        "version": "0.2.0",
        "docs": "/docs",
    }


@app.get("/api/health")
def health():
    return {"status": "ok"}
