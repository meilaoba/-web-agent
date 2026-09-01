"""文档加载器基类与注册表。

设计要点：
1. 每种文件格式一个独立 Loader，职责单一，便于扩展新格式（DOCX、LaTeX 等）。
2. 通过扩展名注册表（DocumentLoaderRegistry）自动分发，新增格式只需注册新 Loader，
   无需修改上层调用代码。
3. 顶层函数 load_documents / load_documents_from_dir 为统一入口，
   支持单个文件与整个目录。
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Type, Union

from ..schemas import Document

logger = logging.getLogger(__name__)

PathLike = Union[str, Path]


class DocumentLoadError(Exception):
    """文档加载失败时抛出，携带文件路径与原因。"""


class BaseDocumentLoader(ABC):
    """所有文档加载器的抽象基类。"""

    #: 支持的扩展名（含点，小写），子类必须声明
    extensions: tuple[str, ...] = ()

    def __init__(
        self,
        file_path: PathLike,
        *,
        encoding: Optional[str] = None,
        category: Optional[str] = None,
        **_: object,
    ) -> None:
        """初始化。

        Args:
            file_path: 文档路径。
            encoding: 文本编码，None 表示自动探测（仅对文本类格式有效）。
            category: 知识分类，例如 owasp_cwe / owasp_top10。
                未提供时从文件所在目录名推导。
        """
        self.file_path = Path(file_path)
        if not self.file_path.is_file():
            raise DocumentLoadError(f"文件不存在: {self.file_path}")
        name = self.file_path.name.lower()
        if self.extensions and not any(name.endswith(ext) for ext in self.extensions):
            logger.warning(
                "Loader %s 声明的扩展名 %s 与文件 %s 不匹配，继续尝试加载",
                type(self).__name__,
                self.extensions,
                self.file_path.name,
            )
        self.encoding = encoding
        self.category = category or self._infer_category()

    # ---------- 抽象接口 ----------
    @abstractmethod
    def load(self) -> List[Document]:
        """将文件加载为 Document 列表（多数格式返回单元素列表）。"""

    # ---------- 通用辅助 ----------
    def _infer_category(self) -> str:
        """从父目录名推导分类，例如 .../raw/owasp_cwe/xx.md -> owasp_cwe。"""
        try:
            return self.file_path.parent.name
        except Exception:  # pragma: no cover - 理论不可达
            return "unknown"

    def _base_metadata(self) -> Dict[str, object]:
        """构造基础元数据：source / document_name / file_type / category。"""
        return {
            "source": str(self.file_path.resolve()),
            "document_name": self.file_path.name,
            "file_type": self.file_path.suffix.lower().lstrip("."),
            "category": self.category,
        }

    def _read_text(self) -> str:
        """读取文本文件，自动探测编码（UTF-8 -> GBK 回退）。"""
        data = self.file_path.read_bytes()
        return _decode_text(data, self.encoding, self.file_path.name)


def _decode_text(data: bytes, encoding: Optional[str], name: str) -> str:
    """按指定编码或自动探测方式解码字节内容。

    编码候选：utf-8（含 BOM）→ gb18030（GBK/GB2312 超集，兼容中文乱码场景）→ latin-1。
    """
    candidates: List[str] = [encoding] if encoding else []
    candidates += ["utf-8", "utf-8-sig", "gb18030", "gbk", "latin-1"]
    last_error: Optional[UnicodeDecodeError] = None
    for enc in candidates:
        if enc is None:
            continue
        try:
            return data.decode(enc)
        except UnicodeDecodeError as exc:  # pragma: no cover - 编码探测路径
            last_error = exc
    raise DocumentLoadError(
        f"无法解码文件 {name}（尝试编码: {candidates}）: {last_error}"
    )


class DocumentLoaderRegistry:
    """按扩展名注册 / 分发文档加载器。"""

    _loaders: Dict[str, Type[BaseDocumentLoader]] = {}

    @classmethod
    def register(
        cls, *extensions: str
    ) -> object:
        """类装饰器：将 Loader 注册到指定扩展名。

        Example:
            @DocumentLoaderRegistry.register(".md", ".markdown")
            class MarkdownLoader(BaseDocumentLoader): ...
        """
        def decorator(loader_cls: Type[BaseDocumentLoader]) -> Type[BaseDocumentLoader]:
            for ext in extensions:
                ext = ext.lower()
                if not ext.startswith("."):
                    ext = f".{ext}"
                if ext in cls._loaders:
                    logger.warning("扩展名 %s 已注册 %s，将被 %s 覆盖", ext, cls._loaders[ext], loader_cls)
                cls._loaders[ext] = loader_cls
            return loader_cls

        return decorator

    @classmethod
    def get_loader_cls(cls, file_path: PathLike) -> Optional[Type[BaseDocumentLoader]]:
        """根据文件扩展名获取 Loader 类，未注册时返回 None。

        支持复合后缀（如 .xml.gz）：按后缀长度降序匹配，优先命中更具体的后缀。
        """
        name = Path(file_path).name.lower()
        for ext in sorted(cls._loaders.keys(), key=len, reverse=True):
            if name.endswith(ext):
                return cls._loaders[ext]
        return None

    @classmethod
    def registered_extensions(cls) -> List[str]:
        """当前已注册的全部扩展名。"""
        return sorted(cls._loaders.keys())


def load_documents(
    file_path: PathLike,
    *,
    encoding: Optional[str] = None,
    category: Optional[str] = None,
) -> List[Document]:
    """加载单个文件为 Document 列表。

    Raises:
        DocumentLoadError: 文件不存在 / 格式不支持 / 解析失败。
    """
    path = Path(file_path)
    loader_cls = DocumentLoaderRegistry.get_loader_cls(path)
    if loader_cls is None:
        raise DocumentLoadError(
            f"不支持的文件格式: {path.suffix}（已注册: {DocumentLoaderRegistry.registered_extensions()}）"
        )
    loader = loader_cls(path, encoding=encoding, category=category)
    logger.info("加载文档: %s (loader=%s)", path.name, loader_cls.__name__)
    docs = loader.load()
    logger.info("文档 %s 加载完成，共 %d 个 Document", path.name, len(docs))
    return docs


def load_documents_from_dir(
    directory: PathLike,
    *,
    extensions: Optional[Sequence[str]] = None,
    recursive: bool = True,
    category: Optional[str] = None,
) -> List[Document]:
    """加载目录下所有支持格式的文件。

    Args:
        directory: 知识数据根目录。
        extensions: 需要加载的扩展名列表，默认取注册表全部格式。
        recursive: 是否递归子目录。
        category: 分类覆盖值；None 时各文件使用自身目录推导的分类。
    """
    root = Path(directory)
    if not root.is_dir():
        raise DocumentLoadError(f"目录不存在: {root}")

    supported = set(DocumentLoaderRegistry.registered_extensions())
    if extensions:
        supported &= {ext if ext.startswith(".") else f".{ext}" for ext in extensions}

    def _matches(name: str) -> bool:
        """文件名是否命中支持的扩展名（含复合后缀，如 .xml.gz）。"""
        return any(name.lower().endswith(ext) for ext in supported)

    if recursive:
        files = [p for p in root.rglob("*") if p.is_file() and _matches(p.name)]
    else:
        files = [p for p in root.glob("*") if p.is_file() and _matches(p.name)]

    files.sort(key=lambda p: str(p).lower())

    docs: List[Document] = []
    failed: List[tuple[Path, str]] = []
    for f in files:
        try:
            docs.extend(load_documents(f, category=category))
        except (DocumentLoadError, OSError) as exc:
            failed.append((f, str(exc)))
            logger.error("加载失败 %s: %s", f, exc)

    logger.info(
        "目录加载完成: %s 共 %d 个文件 -> %d 个 Document（失败 %d 个）",
        root,
        len(files),
        len(docs),
        len(failed),
    )
    if failed:
        logger.warning("失败明细: %s", failed)
    return docs
