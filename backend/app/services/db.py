"""数据库服务层：SQLAlchemy 引擎 / 会话管理。

支持方言：
- sqlite（默认，本地开发与测试）: backend/data/app.db
- mysql（部署，通过 Docker / 本机 MySQL 8）: pymysql://user:pass@host:port/db

切换方式：.env 配置 DB_TYPE=mysql + DB_HOST/DB_PORT/DB_USER/DB_PASSWORD/DB_NAME。
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """所有 ORM 模型的基类。"""


class Database:
    """数据库连接管理（引擎 + 会话工厂）。"""

    def __init__(self, db_type: str, **kwargs) -> None:
        self.db_type = db_type
        if db_type == "mysql":
            url = (
                f"mysql+pymysql://{kwargs['user']}:{kwargs['password']}"
                f"@{kwargs['host']}:{kwargs['port']}/{kwargs['name']}?charset=utf8mb4"
            )
            engine_kwargs = {"pool_pre_ping": True, "pool_recycle": 3600}
        else:
            data_dir = Path(kwargs.get("sqlite_path"))
            data_dir.parent.mkdir(parents=True, exist_ok=True)
            url = f"sqlite:///{data_dir}"
            engine_kwargs = {"connect_args": {"check_same_thread": False}}
        self.engine = create_engine(url, **engine_kwargs)
        self.SessionLocal = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False)
        logger.info("数据库就绪: %s (%s)", url.split("//")[0], self.db_type)

    def create_all(self) -> None:
        """建表（幂等）并执行轻量 schema 迁移。

        create_all 只创建不存在的表，不会为已存在的表补充新增列；
        _migrate 负责为旧库补充本次迭代新增的列（如 users.failed_attempts）。
        """
        from .. import models  # noqa: F401  确保模型注册

        Base.metadata.create_all(self.engine)
        self._migrate()

    def _migrate(self) -> None:
        """轻量幂等迁移：为已存在表补充缺失列（SQLite/MySQL 通用 ADD COLUMN）。"""
        from sqlalchemy import inspect, text

        try:
            inspector = inspect(self.engine)
        except Exception as exc:  # 表尚不存在时跳过
            logger.warning("schema 检查跳过: %s", exc)
            return

        migrations = {
            "users": [
                ("failed_attempts", "INTEGER DEFAULT 0"),
                ("locked_until", "DATETIME"),
            ],
        }
        with self.engine.begin() as conn:
            for table, columns in migrations.items():
                if table not in inspector.get_table_names():
                    continue
                existing = {c["name"] for c in inspector.get_columns(table)}
                for col_name, col_type in columns:
                    if col_name not in existing:
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}"))
                        logger.info("schema 迁移: %s.%s 已补充", table, col_name)

    def drop_all(self) -> None:
        Base.metadata.drop_all(self.engine)

    def get_session(self) -> Generator[Session, None, None]:
        """FastAPI 依赖：请求级会话。"""
        session = self.SessionLocal()
        try:
            yield session
        finally:
            session.close()


#: 全局单例（由 get_database 初始化）
_db: Database | None = None


def get_database() -> Database:
    """获取全局 Database 单例。"""
    global _db
    if _db is None:
        from ..config import settings

        # 支持环境变量 SQLITE_PATH 覆盖（测试隔离用）
        sqlite_path = os.getenv("SQLITE_PATH") or str(settings.data_dir / "app.db")
        _db = Database(
            settings.db_type,
            host=settings.db_host,
            port=settings.db_port,
            user=settings.db_user,
            password=settings.db_password,
            name=settings.db_name,
            sqlite_path=sqlite_path,
        )
    return _db


def init_db() -> None:
    """初始化数据库（建表），供应用启动与测试调用。"""
    db = get_database()
    db.create_all()
