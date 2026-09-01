# 文件上传漏洞（Unrestricted File Upload）

> CWE-434: Unrestricted Upload of File with Dangerous Type
> OWASP 相关：A03:2021 Injection / A01:2021 Broken Access Control

## 漏洞描述

文件上传功能若未对上传文件的类型、内容、大小与存储位置进行有效限制，
攻击者可上传可执行脚本（如 PHP / JSP / 可执行文件）或恶意文件，
配合服务器配置可在服务器上执行任意代码。

## 漏洞成因

1. 仅校验客户端提供的文件扩展名或 MIME 类型，可被伪造绕过；
2. 未校验文件真实内容（文件头魔数），伪装图片的脚本可被上传；
3. 文件直接保存在 Web 可访问目录且未做随机化重命名；
4. 服务器对上传目录配置了脚本执行权限。

## 漏洞影响

- 上传 WebShell，实现远程代码执行；
- 存储型 XSS（上传含恶意脚本的 HTML / SVG）；
- 恶意文件分发（木马、钓鱼附件）；
- 存储耗尽等 DoS 风险。

## 检测方法

- 代码审计：检查上传处理逻辑中扩展名 / 类型 / 内容校验的完整性与绕过可能；
- 动态测试：尝试上传改扩展名的脚本、图片马（含 PHP 内容的图片）等载荷，
  访问上传文件观察是否被执行；
- 检查上传目录的静态资源服务配置。

## 修复方法

1. 白名单校验扩展名与 MIME 类型，并与文件内容魔数双重校验；
2. 随机化重命名文件（如 UUID），避免用户控制文件名；
3. 文件存储在 Web 目录之外，通过受控接口下载 / 预览；
4. 禁止上传目录的脚本执行权限（Nginx 关闭 php 解析等）；
5. 限制文件大小与数量，设置上传频率控制。

## 代码示例

### 漏洞代码（Python Flask）

```python
from flask import request

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    # 仅校验客户端声称的扩展名，可被伪造
    if not file.filename.endswith((".jpg", ".png")):
        return "类型不允许", 400
    # 直接以用户文件名保存到静态目录
    file.save(f"static/uploads/{file.filename}")
    return "上传成功"
```

### 安全代码（Python Flask）

```python
import uuid
from flask import request

ALLOWED_EXT = {".jpg", ".png", ".gif"}
ALLOWED_MAGIC = {b"\xff\xd8\xff", b"\x89PNG", b"GIF8"}

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    ext = "." + file.filename.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_EXT:
        return "类型不允许", 400
    head = file.read(8)
    file.seek(0)
    if not any(head.startswith(m) for m in ALLOWED_MAGIC):
        return "内容校验失败", 400
    # 随机化文件名，存储到 Web 目录之外
    saved_name = f"{uuid.uuid4().hex}{ext}"
    file.save(f"/data/uploads/{saved_name}")
    return "上传成功"
```

## 参考资料

- CWE-434: https://cwe.mitre.org/data/definitions/434.html
- OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
