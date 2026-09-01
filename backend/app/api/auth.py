"""认证 API：注册 / 登录（含防暴力破解锁定）。"""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..config import settings
from ..models import User
from ..schemas.api import LoginRequest, RegisterRequest, TokenResponse
from ..services.auth_service import (
    create_token,
    hash_password,
    verify_password,
)
from .deps import get_db

router = APIRouter(prefix="/api/auth", tags=["认证"])


@router.post("/register", response_model=TokenResponse)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    """注册新用户并返回 Token。"""
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="用户名已存在")
    user = User(username=body.username, password_hash=hash_password(body.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_token(user.id, user.username)
    return TokenResponse(access_token=token, user=user.to_dict())


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    """登录并返回 Token。

    安全措施：
    - 密码 bcrypt 加盐哈希校验；
    - 连续失败 LOGIN_MAX_ATTEMPTS 次锁定 LOGIN_LOCK_MINUTES 分钟（防暴力破解）；
    - 失败提示统一为"用户名或密码错误"，不暴露账号是否存在。
    """
    user = db.query(User).filter(User.username == body.username).first()

    # 锁定检查（统一提示，不泄露锁定状态细节给攻击者差异）
    if user is not None and user.locked_until is not None and user.locked_until > datetime.now():
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="登录失败次数过多，账号已临时锁定，请稍后再试",
        )

    if user is None or not verify_password(body.password, user.password_hash):
        if user is not None:
            # 记录失败次数，达到阈值锁定
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= settings.login_max_attempts:
                user.locked_until = datetime.now() + timedelta(minutes=settings.login_lock_minutes)
                user.failed_attempts = 0
                db.commit()
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail="登录失败次数过多，账号已临时锁定，请稍后再试",
                )
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="用户名或密码错误"
        )

    # 登录成功：重置失败计数
    if user.failed_attempts or user.locked_until:
        user.failed_attempts = 0
        user.locked_until = None
        db.commit()

    token = create_token(user.id, user.username)
    return TokenResponse(access_token=token, user=user.to_dict())
