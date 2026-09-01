"""认证服务：密码哈希（bcrypt）+ JWT Token（PyJWT）。"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt

from ..config import settings

logger = logging.getLogger(__name__)

_JWT_ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    """bcrypt 加盐哈希。"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """校验密码。"""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def create_token(user_id: int, username: str, expires_hours: int = 24 * 7) -> str:
    """签发 JWT。"""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": now,
        "exp": now + timedelta(hours=expires_hours),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=_JWT_ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    """解析 JWT，失败返回 None。"""
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[_JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        logger.debug("Token 解析失败: %s", exc)
        return None
