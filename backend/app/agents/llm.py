"""LLM 客户端模块。

设计（毕设路线 规则7：LLM 必须可替换）：
- LLMClient 为抽象基类，业务代码只依赖该接口；
- OpenAICompatibleLLM：通过 OpenAI 兼容 API 调用（DeepSeek / Qwen / Ollama /
  任意兼容服务），使用 httpx 直接调用 /chat/completions，不引入重型 SDK；
- MockLLM：无 API Key / 离线环境下的确定性实现（规则化输出 + 模拟流式），
  保证 Multi-Agent 流程与对话界面在无网络时可完整测试与演示；
- 通过 settings.llm_provider / llm_* 配置切换 Provider 与模型。

支持的 Provider（配置 .env）：
    LLM_PROVIDER=qwen            # 阿里云百炼（DashScope 兼容模式）
    LLM_API_KEY=sk-xxx
    LLM_MODEL=qwen-max
    # 或本地 Ollama：
    LLM_PROVIDER=ollama
    LLM_BASE_URL=http://localhost:11434/v1
    LLM_MODEL=qwen2.5:7b
    # 或 DeepSeek / OpenAI / 任意 OpenAI 兼容服务：
    LLM_PROVIDER=deepseek / openai / openai_compatible
    LLM_BASE_URL=...   LLM_MODEL=...

使用：
    from app.agents.llm import get_llm_client
    llm = get_llm_client()
    answer = llm.chat("你是安全审计专家", "这段代码有什么问题？")
    for token in llm.chat_stream([{"role": "user", "content": "..."}]):
        print(token, end="")
"""

from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from typing import Dict, Iterator, List, Optional

logger = logging.getLogger(__name__)


class LLMError(Exception):
    """LLM 调用异常。"""


#: Provider -> 默认 Base URL（未显式配置 LLM_BASE_URL 时使用）
PROVIDER_DEFAULT_BASE_URL = {
    "deepseek": "https://api.deepseek.com/v1",
    "openai": "https://api.openai.com/v1",
    "qwen": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "ollama": "http://localhost:11434/v1",
    "local": "http://localhost:11434/v1",
    "openai_compatible": "https://api.deepseek.com/v1",
}


class LLMClient(ABC):
    """LLM 客户端抽象基类。"""

    @abstractmethod
    def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        temperature: Optional[float] = None,
        max_tokens: int = 2048,
    ) -> str:
        """对话补全（一次性返回）。"""

    @abstractmethod
    def chat_stream(
        self,
        messages: List[Dict[str, str]],
        *,
        temperature: Optional[float] = None,
        max_tokens: int = 2048,
    ) -> Iterator[str]:
        """对话补全（流式返回增量文本）。

        Args:
            messages: OpenAI 格式消息列表
                [{"role": "system"|"user"|"assistant", "content": "..."}]
                可携带历史消息实现会话记忆。
        """

    @property
    @abstractmethod
    def name(self) -> str:
        """客户端标识。"""


class OpenAICompatibleLLM(LLMClient):
    """OpenAI 兼容 API 实现（DeepSeek / Qwen / Ollama / OpenAI 等）。"""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.deepseek.com/v1",
        model: str = "deepseek-chat",
        temperature: float = 0.2,
        timeout: float = 120.0,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.timeout = timeout

    @property
    def name(self) -> str:
        return f"openai_compatible({self.model})"

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _payload(self, messages, temperature, max_tokens, stream) -> Dict:
        return {
            "model": self.model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.temperature,
            "max_tokens": max_tokens,
            "stream": stream,
        }

    def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        temperature: Optional[float] = None,
        max_tokens: int = 2048,
    ) -> str:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        return "".join(self._chat_stream_once(messages, temperature, max_tokens, stream=False))

    def chat_stream(
        self,
        messages: List[Dict[str, str]],
        *,
        temperature: Optional[float] = None,
        max_tokens: int = 2048,
    ) -> Iterator[str]:
        yield from self._chat_stream_once(messages, temperature, max_tokens, stream=True)

    def _chat_stream_once(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float],
        max_tokens: int,
        stream: bool,
    ) -> Iterator[str]:
        """底层实现：stream=True 时逐增量 yield，stream=False 时一次性 yield 全文。"""
        try:
            import httpx
        except ImportError as exc:
            raise LLMError("未安装 httpx，无法调用 LLM API") from exc

        payload = self._payload(messages, temperature, max_tokens, stream)
        url = f"{self.base_url}/chat/completions"
        try:
            # 非流式请求使用一次性 POST，避免 stream 模式下需手动 read 才能取 json
            if not stream:
                resp = httpx.post(
                    url, json=payload, headers=self._headers(), timeout=self.timeout
                )
                resp.raise_for_status()
                data = resp.json()
                yield str(data["choices"][0]["message"]["content"])
                return
            with httpx.stream(
                "POST", url, json=payload, headers=self._headers(), timeout=self.timeout
            ) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if not line or not line.startswith("data:"):
                        continue
                    data = line[len("data:"):].strip()
                    if data == "[DONE]":
                        break
                    try:
                        delta = json.loads(data)["choices"][0]["delta"].get("content")
                    except (KeyError, IndexError, json.JSONDecodeError):
                        continue
                    if delta:
                        yield delta
        except LLMError:
            raise
        except Exception as exc:
            raise LLMError(f"LLM API 调用失败: {exc}") from exc


class MockLLM(LLMClient):
    """确定性 Mock 实现（无 API Key 环境）。

    基于关键词规则返回结构化的安全分析结果，chat_stream 按小块输出
    模拟流式效果，保证对话界面离线可演示。生产环境切换真实 Provider。
    """

    def __init__(self) -> None:
        self._call_count = 0

    @property
    def name(self) -> str:
        return "mock"

    def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        temperature: Optional[float] = None,
        max_tokens: int = 2048,
    ) -> str:
        self._call_count += 1
        combined = (system_prompt + "\n" + user_prompt).lower()
        return self._rule_response(combined)

    def chat_stream(
        self,
        messages: List[Dict[str, str]],
        *,
        temperature: Optional[float] = None,
        max_tokens: int = 2048,
    ) -> Iterator[str]:
        self._call_count += 1
        combined = " ".join(str(m.get("content", "")) for m in messages).lower()
        text = self._rule_response(combined)
        # 按小块输出，模拟流式打字效果
        chunk_size = 8
        for i in range(0, len(text), chunk_size):
            yield text[i : i + chunk_size]

    def _rule_response(self, text: str) -> str:
        if "sql" in text or "注入" in text:
            return (
                "判断：存在 SQL 注入风险（CWE-89）。原因：SQL 语句使用字符串拼接，"
                "未使用参数化查询。建议：使用 PreparedStatement / 参数占位符。\n"
                "修复代码示例：\n```python\n"
                "cur.execute('SELECT * FROM users WHERE id=?', (user_id,))\n```"
            )
        if "shell" in text or "命令" in text or "subprocess" in text:
            return (
                "判断：存在命令注入风险（CWE-78）。原因：subprocess 使用了 shell 执行，"
                "或命令字符串拼接用户输入。建议：使用参数列表方式，避免 shell。"
            )
        if "pickle" in text or "反序列化" in text:
            return (
                "判断：存在不安全反序列化风险（CWE-502）。原因：pickle 反序列化不可信数据。"
                "建议：改用 JSON 等安全格式，并校验输入来源。"
            )
        if "eval" in text or "exec" in text:
            return (
                "判断：存在动态代码执行风险（CWE-95）。原因：eval/exec 执行不可信输入。"
                "建议：避免动态执行，使用白名单或安全替代方案。"
            )
        if "ssrf" in text or "requests" in text:
            return (
                "判断：存在 SSRF 风险（CWE-918）。原因：请求 URL 可能来自用户输入。"
                "建议：校验 URL 白名单并拦截内网地址。"
            )
        return (
            "判断：需进一步人工确认。原因：未匹配到已知高危模式。"
            "建议：结合代码上下文与安全知识库复核。"
        )


_PROVIDER_CACHE: Dict[str, LLMClient] = {}


def get_llm_client() -> LLMClient:
    """工厂：按配置返回 LLM 客户端（进程内缓存）。

    Provider 分发规则：
    - LLM_PROVIDER=mock 或未配置 LLM_API_KEY -> MockLLM（离线降级）；
    - LLM_PROVIDER=qwen/deepseek/openai/ollama/local/openai_compatible
      -> OpenAICompatibleLLM（统一 OpenAI 兼容接口，Base URL 按 Provider 默认，
      可通过 LLM_BASE_URL 覆盖）。
    """
    from ..config import settings

    provider = settings.llm_provider.lower()
    if provider in _PROVIDER_CACHE:
        return _PROVIDER_CACHE[provider]

    if provider == "mock" or not settings.llm_api_key:
        client: LLMClient = MockLLM()
        logger.warning(
            "未配置 LLM_API_KEY（或 LLM_PROVIDER=mock），使用 MockLLM（仅开发/测试，生产请配置 API Key）"
        )
    elif provider in PROVIDER_DEFAULT_BASE_URL:
        base_url = settings.llm_base_url or PROVIDER_DEFAULT_BASE_URL[provider]
        model = settings.llm_model
        client = OpenAICompatibleLLM(
            api_key=settings.llm_api_key,
            base_url=base_url,
            model=model,
            temperature=settings.llm_temperature,
        )
        logger.info("LLM 客户端: provider=%s model=%s base_url=%s", provider, model, base_url)
    else:
        raise ValueError(f"未知 LLM_PROVIDER: {settings.llm_provider}（支持: qwen/deepseek/openai/ollama/local/openai_compatible/mock）")

    _PROVIDER_CACHE[provider] = client
    return client


def parse_json_response(text: str) -> Optional[dict]:
    """从 LLM 输出中提取 JSON（容忍 markdown 代码块包裹）。"""
    if not text:
        return None
    cleaned = re.sub(r"```(?:json)?\s*", "", text).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                return None
        return None
