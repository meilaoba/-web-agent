"""Agent 基类与任务上下文。"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from .agent_log import AgentLogger
from .llm import LLMClient

logger = logging.getLogger(__name__)


class AgentContext:
    """Agent 间传递的任务上下文（字典封装）。"""

    def __init__(self, task_id: str, data: Optional[Dict[str, Any]] = None) -> None:
        self.task_id = task_id
        self.data: Dict[str, Any] = data or {}

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self.data[key] = value

    def update(self, mapping: Dict[str, Any]) -> None:
        self.data.update(mapping)

    def to_dict(self) -> Dict[str, Any]:
        return self.data


class BaseAgent(ABC):
    """所有 Agent 的抽象基类。

    职责：统一的执行入口（run + 日志记录），子类实现 _execute。
    """

    name: str = "base"

    def __init__(
        self,
        llm: Optional[LLMClient] = None,
        agent_logger: Optional[AgentLogger] = None,
    ) -> None:
        from .llm import get_llm_client

        self.llm = llm or get_llm_client()
        self.agent_logger = agent_logger

    def run(self, context: AgentContext, **kwargs) -> Dict[str, Any]:
        """执行 Agent 任务并记录日志。

        Returns:
            结果字典（含 agent 名称、任务 id、状态、耗时与具体输出）。
        """
        start = time.time()
        input_summary = self._summarize_input(context, kwargs)
        try:
            output = self._execute(context, **kwargs)
            duration = time.time() - start
            if self.agent_logger:
                self.agent_logger.log(
                    context.task_id,
                    self.name,
                    input_summary,
                    str(output)[:500],
                    status="completed",
                    duration=duration,
                )
            logger.info("[%s] %s 完成，耗时 %.2fs", context.task_id, self.name, duration)
            return {
                "agent": self.name,
                "task_id": context.task_id,
                "status": "completed",
                "duration": round(duration, 3),
                "output": output,
            }
        except Exception as exc:
            duration = time.time() - start
            logger.exception("[%s] %s 执行失败: %s", context.task_id, self.name, exc)
            if self.agent_logger:
                self.agent_logger.log(
                    context.task_id,
                    self.name,
                    input_summary,
                    str(exc),
                    status="failed",
                    duration=duration,
                )
            return {
                "agent": self.name,
                "task_id": context.task_id,
                "status": "failed",
                "duration": round(duration, 3),
                "error": str(exc),
            }

    @abstractmethod
    def _execute(self, context: AgentContext, **kwargs) -> Any:
        """子类实现具体逻辑。"""

    def _summarize_input(self, context: AgentContext, kwargs: Dict[str, Any]) -> str:
        parts = [f"{k}={str(v)[:100]}" for k, v in kwargs.items()]
        return "; ".join(parts) if parts else str(context.to_dict())[:200]
