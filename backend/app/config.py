"""全局配置管理。

设计原则：
1. 配置与代码分离：所有可调参数优先从环境变量 / .env 文件读取。
2. 不硬编码路径：项目相关路径基于代码文件位置推导（PROJECT_ROOT）。
3. 提供合理默认值：未配置时使用适用于本阶段（Phase 1 RAG 数据链路）的默认参数。
4. 为后续阶段预留：Embedding / ChromaDB / LLM 相关配置留出扩展位。

用法：
    from app.config import settings
    settings.chunk_size
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# 项目根目录：backend/app/config.py -> parents[0]=app, [1]=backend, [2]=项目根
PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]

# 加载项目根目录下的 .env（若存在）
load_dotenv(PROJECT_ROOT / ".env")


def _env_int(name: str, default: int) -> int:
    """读取整数环境变量，非法值时回退默认并告警。"""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        logging.getLogger(__name__).warning(
            "环境变量 %s=%r 不是合法整数，使用默认值 %s", name, raw, default
        )
        return default


def _env_str(name: str, default: str) -> str:
    """读取字符串环境变量，未设置时返回默认值。"""
    raw = os.getenv(name)
    return raw.strip() if raw else default


def _env_float(name: str, default: float) -> float:
    """读取浮点环境变量，非法值时回退默认。"""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        logging.getLogger(__name__).warning(
            "环境变量 %s=%r 不是合法浮点数，使用默认值 %s", name, raw, default
        )
        return default


@dataclass(frozen=True)
class Settings:
    """应用全局配置。frozen 防止运行期被意外修改。"""

    # ---------- 路径 ----------
    project_root: Path = PROJECT_ROOT
    backend_dir: Path = PROJECT_ROOT / "backend"
    data_dir: Path = PROJECT_ROOT / "backend" / "data"
    data_raw_dir: Path = field(init=False)
    data_processed_dir: Path = field(init=False)

    # ---------- RAG 文本分割参数 ----------
    chunk_size: int = field(default_factory=lambda: _env_int("CHUNK_SIZE", 800))
    chunk_overlap: int = field(default_factory=lambda: _env_int("CHUNK_OVERLAP", 100))

    # ---------- 清洗参数 ----------
    # 判为"噪声行"的正则模式（保守匹配，避免误删安全知识）
    noise_line_patterns: tuple[str, ...] = (
        r"^\s*(首页|返回首页|返回顶部|更多|加载更多)\s*$",
        r"^\s*(联系我们|关于我们|网站地图|隐私政策|使用条款|免责声明)\s*$",
        r"^\s*(上一篇|下一篇)[:：]?.*$",
        r"^\s*(上一页|下一页)\s*$",
        r"^\s*(登录|注册|免费注册|立即登录)\s*$",
        r"^\s*[©©]\s*.*(reserved|版权所有|版权声明).*$",
        r"^\s*(版权所有|Copyright).*$",
        r"^\s*All rights reserved.*$",
        r"^\s*(浏览人数|访问量|点击量|阅读量)[:：]?\s*[\d,]+.*$",
        r"^\s*(分享到|转发到)\s*(微信|微博|QQ|朋友圈).*$",
        r"^\s*cookie(s)?\s*(同意|政策|提示).*$",
    )

    # ---------- 日志 ----------
    log_level: str = field(default_factory=lambda: _env_str("LOG_LEVEL", "INFO"))

    # ---------- Embedding ----------
    # embedding 提供方: bge_m3(本地模型) / hashing(降级,测试用)
    embedding_provider: str = field(default_factory=lambda: _env_str("EMBEDDING_PROVIDER", "hashing"))
    # BGE-M3 模型名或本地路径
    embedding_model: str = field(default_factory=lambda: _env_str("EMBEDDING_MODEL", "BAAI/bge-m3"))
    embedding_device: str = field(default_factory=lambda: _env_str("EMBEDDING_DEVICE", "cpu"))
    embedding_dimension: int = field(default_factory=lambda: _env_int("EMBEDDING_DIMENSION", 256))

    # ---------- ChromaDB ----------
    chroma_dir: Path = field(init=False)
    chroma_collection: str = field(default_factory=lambda: _env_str("CHROMA_COLLECTION", "security_knowledge"))

    # ---------- 检索 ----------
    retrieval_top_k: int = field(default_factory=lambda: _env_int("RETRIEVAL_TOP_K", 5))
    rerank_enabled: bool = field(default_factory=lambda: _env_str("RERANK_ENABLED", "true").lower() == "true")

    # ---------- LLM ----------
    llm_provider: str = field(default_factory=lambda: _env_str("LLM_PROVIDER", "openai_compatible"))
    llm_api_key: str = field(default_factory=lambda: _env_str("LLM_API_KEY", ""))
    # 空值表示按 Provider 使用默认 Base URL（deepseek/openai/qwen/ollama）
    llm_base_url: str = field(default_factory=lambda: _env_str("LLM_BASE_URL", ""))
    llm_model: str = field(default_factory=lambda: _env_str("LLM_MODEL", "deepseek-chat"))
    llm_temperature: float = field(
        default_factory=lambda: _env_float("LLM_TEMPERATURE", 0.2)
    )

    # ---------- 数据库 ----------
    # 支持: sqlite（默认，本地验证）/ mysql（部署）
    db_type: str = field(default_factory=lambda: _env_str("DB_TYPE", "sqlite"))
    db_host: str = field(default_factory=lambda: _env_str("DB_HOST", "127.0.0.1"))
    db_port: int = field(default_factory=lambda: _env_int("DB_PORT", 3306))
    db_user: str = field(default_factory=lambda: _env_str("DB_USER", "root"))
    db_password: str = field(default_factory=lambda: _env_str("DB_PASSWORD", ""))
    db_name: str = field(default_factory=lambda: _env_str("DB_NAME", "ai_security_audit"))

    # ---------- 服务 ----------
    upload_dir: Path = field(init=False)
    api_host: str = field(default_factory=lambda: _env_str("API_HOST", "127.0.0.1"))
    api_port: int = field(default_factory=lambda: _env_int("API_PORT", 8000))
    # CORS 允许的来源（逗号分隔；留空=允许所有来源，适用于开发环境）
    cors_origins: str = field(default_factory=lambda: _env_str("CORS_ORIGINS", ""))

    # ---------- 安全 ----------
    # JWT 签名密钥（生产环境务必通过 .env 设置随机值）
    jwt_secret: str = field(default_factory=lambda: _env_str(
        "JWT_SECRET", "dev-secret-do-not-use-in-production"
    ))
    token_expire_hours: int = field(default_factory=lambda: _env_int("TOKEN_EXPIRE_HOURS", 168))
    # 防暴力破解：连续失败锁定
    login_max_attempts: int = field(default_factory=lambda: _env_int("LOGIN_MAX_ATTEMPTS", 5))
    login_lock_minutes: int = field(default_factory=lambda: _env_int("LOGIN_LOCK_MINUTES", 15))

    def __post_init__(self) -> None:
        # 环境变量可覆盖数据目录（保持 dataclass frozen 语义下用 object.__setattr__）
        raw_dir = os.getenv("DATA_RAW_DIR")
        processed_dir = os.getenv("DATA_PROCESSED_DIR")
        object.__setattr__(
            self,
            "data_raw_dir",
            (PROJECT_ROOT / raw_dir) if raw_dir else (self.data_dir / "raw"),
        )
        object.__setattr__(
            self,
            "data_processed_dir",
            (PROJECT_ROOT / processed_dir)
            if processed_dir
            else (self.data_dir / "processed"),
        )
        object.__setattr__(
            self,
            "chroma_dir",
            _pick_ascii_dir(
                os.getenv("CHROMA_DIR"),
                self.data_dir / "chroma",
                Path(os.environ.get("TEMP", "C:/temp")) / "ai-audit-chroma",
            ),
        )
        object.__setattr__(
            self,
            "upload_dir",
            self.data_dir / "uploads",
        )


def _pick_ascii_dir(*candidates) -> Path:
    """从候选中选择第一个纯 ASCII 路径。

    原因：chroma-hnswlib（C++ 扩展）在含非 ASCII（如中文）路径下无法
    持久化 HNSW 索引（写入静默失败，重启后检索报 'Cannot open header file'）。
    候选顺序：CHROMA_DIR 环境变量 > 默认数据目录 > 系统临时目录。
    """
    for cand in candidates:
        if cand is None:
            continue
        path = Path(cand)
        try:
            str(path).encode("ascii")
            return path
        except UnicodeEncodeError:
            continue
    # 兜底：当前目录下的相对路径（ASCII）
    return Path("chroma_data")


# 全局单例，模块内统一从 settings 取配置
settings = Settings()

# 支持的文档扩展名（loader 注册表以此为准）
SUPPORTED_EXTENSIONS: tuple[str, ...] = (".md", ".markdown", ".txt", ".json", ".html", ".htm", ".pdf")


def setup_logging() -> None:
    """初始化全局日志。"""
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
