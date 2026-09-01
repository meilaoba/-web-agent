# 服务端请求伪造（SSRF）

> CWE-918: Server-Side Request Forgery
> OWASP A10:2021 - Server-Side Request Forgery

## 漏洞描述

服务端请求伪造（SSRF）指攻击者能够控制服务端发起的 HTTP 请求的目标地址，
使服务端代为访问攻击者指定的内网或外部资源，从而探测内网、读取敏感文件
或攻击内网服务。

常见触发场景：URL 预览、图片抓取、Webhook 配置、代理转发等功能，
接收用户提供的 URL 后由服务端直接请求。

## 漏洞成因

1. 服务端直接使用用户可控的 URL 发起请求，未校验协议、域名与端口；
2. 缺少对内网地址段（127.0.0.1、10.x、172.16-31.x、192.168.x、169.254.169.254 等）
   的拦截；
3. 仅做字符串黑名单过滤，可被 DNS 重绑定、URL 编码、IP 进制转换等绕过。

## 漏洞影响

- 探测内网拓扑与开放端口；
- 访问云元数据服务（如 169.254.169.254）窃取临时凭证；
- 读取本地文件（配合 file:// 协议）；
- 以内网身份发起进一步攻击。

## 检测方法

- 代码审计：追踪用户输入流向 HTTP 客户端请求 URL 的路径；
- 动态测试：提交内网地址、云元数据地址、file:// 等不同协议载荷，
  观察响应内容或访问日志；
- 关注解析差异：同一 URL 在服务端解析结果与校验结果不一致的绕过。

## 修复方法

1. URL 白名单：只允许请求预定义的受信域名；
2. 协议白名单：仅允许 http/https，禁止 file、gopher 等危险协议；
3. 禁止请求内网 / 保留地址段，并对 DNS 解析结果做二次校验
   （防止 DNS 重绑定绕过）；
4. 请求响应不直接回显给用户，或仅回显白名单字段；
5. 出方向部署防火墙 / 代理限制。

## 代码示例

### 漏洞代码（Python）

```python
import requests

url = request.args.get("url")          # 用户可控
resp = requests.get(url, timeout=5)    # 服务端直接请求
return resp.text
```

### 安全代码（Python，白名单 + 内网拦截）

```python
import ipaddress
import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = {"example.com", "api.example.com"}

url = request.args.get("url")
host = urlparse(url).hostname
if host not in ALLOWED_HOSTS:
    raise ValueError("URL 不在白名单内")

# 解析 DNS 并拦截内网地址，防止 DNS 重绑定
for addr in _resolve_all(host):
    if not ipaddress.ip_address(addr).is_global:
        raise ValueError("禁止访问内网地址")

resp = requests.get(url, timeout=5)
return resp.text
```

## 参考资料

- CWE-918: https://cwe.mitre.org/data/definitions/918.html
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
