"""pytest 公共配置。

- 将 backend 目录加入 sys.path（允许以 pytest 直接运行）；
- 提供测试 fixtures 路径与动态生成的 PDF 样例；
- API 测试使用独立的 SQLite 数据库（SQLITE_PATH 环境变量覆盖）。
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

# backend 目录（app 包所在位置）
BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# 测试环境强制使用 MockLLM（app.config 加载 .env 时 load_dotenv 不覆盖已存在的
# 环境变量，因此不会读到用户配置的真实 API Key，避免测试调用真实模型）
os.environ["LLM_API_KEY"] = ""
os.environ["LLM_PROVIDER"] = "mock"

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PROJECT_ROOT = BACKEND_DIR.parent


@pytest.fixture(scope="session", autouse=True)
def isolated_db(tmp_path_factory):
    """API 测试使用独立 SQLite 数据库，并重置 Database 单例。"""
    db_path = tmp_path_factory.mktemp("test_db") / "test_app.db"
    os.environ["SQLITE_PATH"] = str(db_path)
    os.environ["DB_TYPE"] = "sqlite"
    from app.services import db as db_module

    db_module._db = None  # 重置单例，使 get_database 使用新路径
    from app.services.db import init_db

    init_db()
    yield db_path


def _load_build_pdf():
    """从文件路径加载 PDF 生成器（避免依赖 scripts 为包）。"""
    module_path = PROJECT_ROOT / "scripts" / "data_pipeline" / "make_sample_pdf.py"
    spec = importlib.util.spec_from_file_location("make_sample_pdf", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_pdf


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """测试样例数据目录。"""
    return FIXTURES_DIR


@pytest.fixture(scope="session")
def sample_pdf(tmp_path_factory) -> Path:
    """动态生成 PDF 样例（避免把二进制文件提交到版本库）。"""
    output = tmp_path_factory.mktemp("pdf_fixtures") / "sample.pdf"
    return _load_build_pdf()(output)


@pytest.fixture(scope="session")
def client():
    """FastAPI TestClient（共享会话内数据库）。"""
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c
