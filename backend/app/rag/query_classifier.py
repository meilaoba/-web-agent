"""安全问题意图分类器。

作用：区分"Web 安全 / 代码安全 / 漏洞分析 / 安全开发"类问题与普通闲聊，
避免普通问题（你好 / 你是谁 / 谢谢 等）触发昂贵的 RAG 检索。

设计（非简单关键词匹配）：
1. **强安全问题信号**：Web 安全专有术语（注入 / XSS / CWE / 漏洞 / 越权 等）；
2. **普通闲聊信号**：问候 / 身份 / 致谢 / 时间等闲聊词（优先级次于安全词，
   如"你好，什么是SQL注入？"仍判定为安全）；
3. **代码上下文信号**：含代码 / 函数 / 接口 / 分析 等词视为代码安全分析；
4. **对话上下文**：当前问题无明确信号时，若上一条用户消息是安全问题，
   则继承为安全（如"那怎么修复？"承接 SQL 注入话题）；
5. 均无信号 → 默认普通问题（保守，避免误触发 RAG）。

如需更强意图判断，可在此之上接入 LLM 分类（is_security_query），
但规则层已覆盖绝大多数场景且零成本。
"""

from __future__ import annotations

from typing import Optional

#: 强安全问题信号（命中即视为安全问题）
SECURITY_TERMS: tuple[str, ...] = (
    # 注入类
    "sql注入", "sql injection", "sqli",
    "xss", "跨站脚本", "cross-site scripting",
    "csrf", "跨站请求伪造",
    "ssrf", "服务端请求伪造",
    "xxe", "xml外部实体", "xml external entity",
    "命令注入", "command injection",
    "rce", "远程代码执行",
    "注入", "injection",
    # 序列化 / 代码执行
    "反序列化", "deserialization", "pickle",
    "eval", "exec",
    # 文件与路径
    "路径遍历", "目录穿越", "path traversal",
    "文件上传", "file upload",
    # 认证与授权
    "越权", "未授权", "权限提升", "提权", "权限绕过",
    "认证", "授权", "权限控制", "access control",
    "暴力破解", "弱口令", "弱密码",
    # 编码与数据
    "cwe", "cve", "owasp",
    "漏洞", "脆弱性", "vulnerab",
    "缓冲区溢出", "buffer overflow", "整数溢出",
    "格式化字符串", "拒绝服务", "dos攻击",
    "webshell", "木马", "后门", "恶意代码", "恶意文件",
    "钓鱼", "phishing",
    "加密", "解密", "ssl", "tls", "https",
    "payload", "exploit", "漏洞利用", "攻击面",
    "渗透", "安全测试", "安全扫描", "安全审计", "代码审计",
    "安全风险", "安全问题", "安全漏洞", "代码安全", "安全开发",
    "泄露", "泄漏", "篡改", "伪造", "绕过", "注入点",
    "修复", "防护", "防御", "防范", "缓解", "检测方法",
)

#: 代码分析上下文信号（辅助判定"分析这段代码"类问题）
CODE_TERMS: tuple[str, ...] = (
    "代码", "code", "函数", "方法", "接口", "参数",
    "请求", "response", "request", "程序", "脚本",
    "变量", "语句", "源码", "逻辑", "片段", "实现",
    "分析", "审查", "检查", "评估", "跑一下", "执行",
)

#: 普通闲聊强信号（命中且无安全信号时为普通问题）
GENERAL_TERMS: tuple[str, ...] = (
    "你好", "您好", "hi", "hello", "hey", "哈喽",
    "你是谁", "你叫什么", "你能做什么", "会做什么", "介绍一下你自己", "自我介绍",
    "谢谢", "感谢", "多谢", "再见", "拜拜", "晚安", "早安",
    "几点", "时间", "天气", "新闻", "股市", "你好吗", "在吗",
    "今天", "周末", "吃饭", "开玩笑",
)


def classify_security_query(
    query: str, last_user_message: Optional[str] = None
) -> bool:
    """判断问题是否属于 Web 安全 / 代码安全相关。

    Args:
        query: 当前用户问题。
        last_user_message: 上一条用户消息（用于对话上下文继承）。

    Returns:
        True = 安全问题（应执行 RAG）；False = 普通问题（直接 LLM）。
    """
    q = query.lower().strip()

    # 1. 强安全问题信号（优先于闲聊，如"你好，什么是SQL注入？"）
    if any(term in q for term in SECURITY_TERMS):
        return True

    # 2. 普通闲聊信号
    if any(term in q for term in GENERAL_TERMS):
        return False

    # 3. 对话上下文继承：无明确信号且上一条是安全问题（如"那怎么修复？"）
    if last_user_message and not q:
        return classify_security_query(last_user_message)

    # 4. 代码分析上下文（"分析这段代码…"）
    if any(term in q for term in CODE_TERMS):
        return True

    # 5. 默认普通问题（保守，避免误触发 RAG）
    return False
