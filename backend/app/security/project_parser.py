"""项目解析模块：代码上传 / 解压 / 文件收集 / 语言识别。

安全要点：
- 解压时防止 Zip Slip（路径穿越）：拒绝含 .. 或绝对路径的条目；
- 仅收集目标代码文件扩展名，跳过依赖目录（node_modules/.git/dist 等）；
- 语言识别基于文件扩展名统计。
"""

from __future__ import annotations

import logging
import shutil
import zipfile
from collections import Counter
from pathlib import Path
from typing import Dict, List, Sequence, Set

logger = logging.getLogger(__name__)


class ProjectParseError(Exception):
    """项目解析异常。"""


#: 支持扫描的代码文件扩展名 -> 语言
LANGUAGE_EXTENSIONS: Dict[str, str] = {
    ".py": "python",
    ".java": "java",
    ".jsp": "java",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".vue": "javascript",
    ".php": "php",
    ".go": "go",
    ".rb": "ruby",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "css",
    ".sql": "sql",
    ".json": "json",
    ".xml": "xml",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".sh": "shell",
    ".bat": "shell",
    ".ps1": "powershell",
}

#: 跳过的目录（任意层级）：依赖 / VCS / 编译产物 / 缓存
IGNORED_DIRS: Set[str] = {
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    ".idea",
    ".vscode",
    "dist",
    "build",
    "target",
    "out",
    "bin",
    ".gradle",
    ".mvn",
    ".next",
    ".nuxt",
    "coverage",
    "__pycache__",
    ".pytest_cache",
    "venv",
    ".venv",
    ".deps",
    "vendor",
}

#: 跳过的文件
IGNORED_FILES: Set[str] = {".DS_Store", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}


class ProjectParser:
    """解析上传的代码项目。"""

    def __init__(self, work_dir: Path | str) -> None:
        """初始化。

        Args:
            work_dir: 项目工作根目录（解压与扫描均在此目录内进行）。
        """
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)

    # ---------- 上传与解压 ----------
    def extract_zip(self, zip_path: Path | str, target_name: str) -> Path:
        """安全解压 zip 到 work_dir/target_name。

        zip 条目若全部位于同一顶层目录（常见打包方式），解压时自动展开该层。

        Raises:
            ProjectParseError: zip 损坏 / 存在路径穿越条目 / 目标已存在。
        """
        zip_path = Path(zip_path)
        target = self.work_dir / target_name
        if target.exists():
            raise ProjectParseError(f"目标目录已存在: {target}")

        target.mkdir(parents=True)
        try:
            with zipfile.ZipFile(zip_path) as zf:
                names = zf.namelist()
                strip_root = _single_root_dir(names)
                for info in zf.infolist():
                    entry = info.filename
                    if strip_root:
                        parts = entry.replace("\\", "/").split("/")
                        if len(parts) > 1:
                            entry = "/".join(parts[1:])
                        else:
                            continue  # 根目录条目本身
                    dest = self._safe_join(target, entry)
                    if info.is_dir():
                        dest.mkdir(parents=True, exist_ok=True)
                        continue
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info) as src, open(dest, "wb") as out:
                        shutil.copyfileobj(src, out)
        except zipfile.BadZipFile as exc:
            shutil.rmtree(target, ignore_errors=True)
            raise ProjectParseError(f"无效的 zip 文件: {exc}") from exc
        except ProjectParseError:
            shutil.rmtree(target, ignore_errors=True)
            raise
        logger.info("解压完成: %s -> %s", zip_path.name, target)
        return target

    @staticmethod
    def _safe_join(base: Path, filename: str) -> Path:
        """防 Zip Slip：拒绝绝对路径与 .. 逃逸。"""
        # 统一分隔符并清理
        normalized = filename.replace("\\", "/")
        parts = [p for p in normalized.split("/") if p not in ("", ".")]
        if any(p == ".." for p in parts):
            raise ProjectParseError(f"检测到路径穿越条目: {filename}")
        dest = base.joinpath(*parts)
        # 兜底校验
        if not str(dest.resolve()).startswith(str(base.resolve())):
            raise ProjectParseError(f"非法路径条目: {filename}")
        return dest

    # ---------- 文件收集与语言识别 ----------
    def collect_source_files(self, project_dir: Path | str) -> List[Path]:
        """收集项目中的目标代码文件（跳过依赖目录）。"""
        root = Path(project_dir)
        if not root.is_dir():
            raise ProjectParseError(f"项目目录不存在: {root}")
        files: List[Path] = []
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if p.name in IGNORED_FILES:
                continue
            if any(part in IGNORED_DIRS for part in p.relative_to(root).parts):
                continue
            if p.suffix.lower() in LANGUAGE_EXTENSIONS:
                files.append(p)
        files.sort(key=lambda p: str(p).lower())
        logger.info("收集到 %d 个代码文件（%s）", len(files), root)
        return files

    def detect_language(self, files: Sequence[Path]) -> str:
        """按扩展名统计识别项目主语言。"""
        counter: Counter[str] = Counter()
        for f in files:
            lang = LANGUAGE_EXTENSIONS.get(f.suffix.lower())
            if lang:
                counter[lang] += 1
        if not counter:
            return "unknown"
        return counter.most_common(1)[0][0]

    def read_file(self, path: Path, max_bytes: int = 200_000) -> str:
        """读取代码文件内容（限制大小，超过截断）。"""
        try:
            data = path.read_bytes()[:max_bytes]
            for enc in ("utf-8", "utf-8-sig", "gbk", "latin-1"):
                try:
                    return data.decode(enc)
                except UnicodeDecodeError:
                    continue
            return data.decode("utf-8", errors="replace")
        except OSError as exc:
            raise ProjectParseError(f"读取文件失败 {path}: {exc}") from exc


def _single_root_dir(names: List[str]) -> bool:
    """判断 zip 条目是否都位于同一个顶层目录（若是则解压时展开该层）。

    例如 ['proj/app.py', 'proj/README.md'] -> True（解压到 target/app.py）。
    拒绝危险顶层（.. / . / 空），避免绕过路径穿越校验。
    """
    if not names:
        return False
    roots = {n.replace("\\", "/").split("/")[0] for n in names if n}
    if len(roots) != 1:
        return False
    root = roots.pop()
    if root in ("..", ".", "") or "/" in root or "\\" in root:
        return False
    # 顶层必须确实是一个目录（存在 root/ 条目或至少一个 root/xxx 条目）
    for n in names:
        normalized = n.replace("\\", "/")
        if normalized == root or normalized.startswith(root + "/"):
            return True
    return False
