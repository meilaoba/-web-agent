# 认证与授权问题（Authentication & Authorization）

> CWE-287: Improper Authentication
> CWE-306: Missing Authentication for Critical Function
> CWE-862: Missing Authorization
> OWASP A07:2021 - Identification and Authentication Failures
> OWASP A01:2021 - Broken Access Control

## 漏洞描述

认证（Authentication）确认"你是谁"，授权（Authorization）确认"你能做什么"。
两类问题在 Web 应用中普遍存在且经常同时出现：

- 认证缺陷：弱口令、暴力破解、会话固定、登录逻辑可绕过、凭据泄露；
- 授权缺陷：越权访问（水平越权访问他人数据、垂直越权执行管理员操作）、
  未授权访问管理接口、IDOR（不安全直接对象引用）。

## 漏洞成因

1. 登录认证逻辑只校验客户端可控条件（如 Cookie 中的用户 ID），
   缺少服务端会话绑定；
2. 敏感接口缺少权限校验，或仅在前端隐藏按钮；
3. 使用对象 ID 直接查询资源，未校验归属（IDOR）；
4. 会话管理不当：无超时、无失效机制、可预测 Session ID；
5. 弱口令策略与缺少防暴力破解机制。

## 漏洞影响

- 账户接管与身份冒充；
- 越权读取 / 修改他人数据，破坏数据机密性与完整性；
- 提权至管理员，接管系统。

## 检测方法

- 代码审计：检查所有敏感接口的服务端权限校验逻辑；
- 动态测试：直接构造其他用户的资源 ID 请求（IDOR 验证）；
- 检查会话 Cookie 属性、登录失败处理、密码策略；
- 遍历接口清单，验证未登录 / 低权限用户可访问的接口。

## 修复方法

1. 认证：服务端集中鉴权，密码使用强哈希（bcrypt / argon2）加盐存储，
   登录失败限速与锁定，设置会话超时与失效机制；
2. 授权：基于角色的访问控制（RBAC），每个接口强制校验权限；
3. 资源访问一律校验归属（当前用户 ID 与资源属主一致）；
4. 管理功能单独加强校验，不依赖前端隐藏；
5. 会话 ID 随机化，Cookie 设置 `Secure` / `HttpOnly` / `SameSite`。

## 代码示例

### 漏洞代码（Python Flask，越权 / IDOR）

```python
from flask import request

@app.route("/order/<int:order_id>")
def get_order(order_id):
    # 仅按传入 ID 查询，未校验订单归属
    order = db.query("SELECT * FROM orders WHERE id=?", (order_id,))
    return order
```

### 安全代码（Python Flask，校验归属）

```python
from flask import request, abort

@app.route("/order/<int:order_id>")
def get_order(order_id):
    user_id = session["user_id"]
    order = db.query(
        "SELECT * FROM orders WHERE id=? AND user_id=?",
        (order_id, user_id),   # 归属校验
    )
    if order is None:
        abort(404)
    return order
```

### 漏洞代码（Java，缺失认证）

```java
@WebServlet("/admin/deleteUser")
public class AdminServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        // 未校验管理员权限，任何登录用户都可调用
        userService.deleteUser(req.getParameter("id"));
    }
}
```

### 安全代码（Java，RBAC 校验）

```java
@WebServlet("/admin/deleteUser")
public class AdminServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        if (!currentUser(req).hasRole("ADMIN")) {
            resp.sendError(403, "无权限");
            return;
        }
        userService.deleteUser(req.getParameter("id"));
    }
}
```

## 参考资料

- CWE-287: https://cwe.mitre.org/data/definitions/287.html
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
- OWASP Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
