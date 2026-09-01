"""Agent 执行日志（毕设路线 26）。

记录每个 Agent 的执行过程：agent_name / task_id / input / output /
status / start_time / end_time / duration，供前端展示"Agent 执行过程"
与答辩演示。

实现：JSONL 落盘（文件日志），同时可注入数据库存储（后端阶段）。
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class AgentLogEntry:
    """单条 Agent 执行记录。"""

    agent_name: str
    task_id: str
    input_summary: str
    output_summary: str
    status: str = "completed"          # running / completed / failed
    duration: float = 0.0
    start_time: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "task_id": self.task_id,
            "input_summary": self.input_summary,
            "output_summary": self.output_summary,
            "status": self.status,
            "duration": round(self.duration, 3),
            "start_time": self.start_time,
            "details": self.details,
        }


class AgentLogger:
    """Agent 执行日志记录器（线程安全，JSONL 落盘）。"""

    def __init__(self, log_dir: Path | str) -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # 按任务 id 映射日志文件（并发任务各写各的文件，避免串写）
        self._files: Dict[str, Path] = {}
        self._entries: Dict[str, list] = {}

    # ---------- 任务级 ----------
    def start_task(self, task_id: Optional[str] = None) -> str:
        """开启一个新审计任务，返回 task_id。"""
        tid = task_id or f"task-{uuid.uuid4().hex[:12]}"
        self._entries[tid] = []
        self._files[tid] = self.log_dir / f"{tid}.jsonl"
        logger.info("Agent 日志任务开启: %s", tid)
        return tid

    # ---------- 记录 ----------
    def log(
        self,
        task_id: str,
        agent_name: str,
        input_summary: str,
        output_summary: str = "",
        *,
        status: str = "completed",
        duration: float = 0.0,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        entry = AgentLogEntry(
            agent_name=agent_name,
            task_id=task_id,
            input_summary=input_summary[:500],
            output_summary=output_summary[:500],
            status=status,
            duration=duration,
            details=details or {},
        )
        with self._lock:
            self._entries.setdefault(task_id, []).append(entry)
            log_file = self._files.get(task_id)
            if log_file is not None:
                with log_file.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")

    def log_call(
        self,
        task_id: str,
        agent_name: str,
        input_summary: str,
        fn,
        **fn_kwargs,
    ):
        """执行 fn 并记录耗时与结果摘要。"""
        start = time.time()
        try:
            result = fn(**fn_kwargs)
            output = str(result)[:500]
            self.log(
                task_id, agent_name, input_summary, output,
                status="completed", duration=time.time() - start,
            )
            return result
        except Exception as exc:
            self.log(
                task_id, agent_name, input_summary, str(exc),
                status="failed", duration=time.time() - start,
            )
            raise

    # ---------- 读取 ----------
    def get_task_logs(self, task_id: str) -> list[Dict[str, Any]]:
        """读取任务的完整执行链（按记录顺序）。"""
        with self._lock:
            return [e.to_dict() for e in self._entries.get(task_id, [])]

    def read_task_file(self, task_id: str) -> list[Dict[str, Any]]:
        """从文件读取任务日志（进程重启后仍可用）。"""
        path = self.log_dir / f"{task_id}.jsonl"
        if not path.is_file():
            return []
        entries = []
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def list_tasks(self) -> list[str]:
        """列出已记录的任务 id。"""
        return sorted(p.stem for p in self.log_dir.glob("*.jsonl"))


#: 全局单例（进程内共享）
_default_logger: Optional[AgentLogger] = None


def get_agent_logger(log_dir: Optional[Path | str] = None) -> AgentLogger:
    """获取全局 AgentLogger 单例。"""
    global _default_logger
    if _default_logger is None:
        from ..config import settings

        _default_logger = AgentLogger(log_dir or (settings.data_dir / "agent_logs"))
    return _default_logger
