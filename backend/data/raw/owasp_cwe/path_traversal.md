# 路径遍历（Path Traversal）

> CWE-22: Improper Limitation of a Pathname to a Restricted Directory
> OWASP A01:2021 - Broken Access Control

## 漏洞描述

路径遍历（目录穿越）发生在应用程序使用用户可控输入拼接文件路径，
且未限制在指定目录范围内时。攻击者通过 `../` 等相对路径序列
可读取或写入服务器上的任意文件。

常见载荷：

```text
../../../../etc/passwd
..\..\..\..\windows\win.ini
....//....//....//etc/passwd        (过滤 . 和 / 时的绕过)
%2e%2e%2f%2e%2e%2fetc%2fpasswd      (URL 编码绕过)
```

## 漏洞成因

1. 使用用户输入直接拼接文件路径（`os.path.join`、`open(path)` 等）；
2. 缺少对路径规范化后是否位于允许目录内的校验；
3. 过滤不完整：未覆盖编码、大小写、多斜杠等变形。

## 漏洞影响

- 读取敏感文件（配置文件、源码、密码文件）；
- 配合写入场景可覆盖应用文件，导致篡改或 RCE；
- 泄露系统与业务敏感信息。

## 检测方法

- 代码审计：追踪文件读写操作的路径参数来源；
- 动态测试：提交 `../`、编码绕过、绝对路径等载荷，观察响应中的文件内容；
- 验证路径规范化（`os.path.realpath` / `Path.resolve`）后是否越界。

## 修复方法

1. 使用白名单 ID 映射真实文件名，避免直接使用用户输入作为路径；
2. 必须使用时，先规范化路径（realpath），再校验前缀是否位于允许的
   根目录内（`path.startswith(root + os.sep)`）；
3. 拒绝包含 `..`、空字节、绝对路径的输入；
4. 文件访问层统一封装，集中做目录约束校验。

## 代码示例

### 漏洞代码（Python）

```python
from flask import request, send_file

filename = request.args.get("filename")
# 用户输入直接拼接路径
return send_file(f"/data/docs/{filename}")
```

### 安全代码（Python）

```python
import os
from pathlib import Path
from flask import request, send_file

BASE_DIR = Path("/data/docs").resolve()

filename = request.args.get("filename")
if filename is None or ".." in filename or filename.startswith(("/", "\\")):
    raise ValueError("非法文件名")

target = (BASE_DIR / filename).resolve()
if BASE_DIR not in target.parents:
    raise ValueError("路径越界")

return send_file(target)
```

## 参考资料

- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- OWASP Path Traversal: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include.html
