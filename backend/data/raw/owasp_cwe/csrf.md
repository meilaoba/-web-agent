# 跨站请求伪造（CSRF）

> CWE-352: Cross-Site Request Forgery
> OWASP 相关：A01:2021 Broken Access Control（2017 版为 A08）

## 漏洞描述

跨站请求伪造（CSRF）指攻击者诱导已登录用户访问恶意页面，
恶意页面自动向目标站点发起携带用户 Cookie 的请求，执行用户未授权的操作
（转账、改密、删除数据等）。

由于浏览器会自动附带目标站点的 Cookie，服务端难以仅凭请求本身
区分请求是否由用户真实意图发起。

## 漏洞成因

1. 状态变更请求（POST / PUT / DELETE）仅依赖 Cookie 认证，无额外校验；
2. 缺少 CSRF Token、`SameSite` Cookie 等防护；
3. 部分站点将 Cookie 作用域设置过宽（不设 SameSite）。

## 漏洞影响

- 以受害者身份执行任意状态变更操作；
- 批量利用可造成资金损失、数据破坏；
- 与 XSS 结合时危害进一步放大。

## 检测方法

- 代码审计：检查所有状态变更接口是否校验 CSRF Token / 来源头；
- 动态测试：构造跨站表单 / 图片请求，观察目标接口是否接受
  不带 Token 的请求；
- 检查 Cookie 的 `SameSite` 属性配置。

## 修复方法

1. **同步 Token 模式**：为会话绑定随机 Token，写入表单隐藏域，
   服务端校验 Token 与来源；
2. **Double Submit Cookie**：Token 同时放在 Cookie 与请求参数中，服务端比对；
3. Cookie 设置 `SameSite=Lax/Strict`（现代浏览器默认防护）；
4. 关键操作增加二次校验（图形验证码、短信验证）；
5. 校验 `Origin` / `Referer` 头作为纵深防御（注意其可缺失场景）。

## 代码示例

### 漏洞代码（Java Servlet）

```java
@WebServlet("/transfer")
public class TransferServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        // 仅依赖会话 Cookie 即可完成转账，无 CSRF 防护
        String to = req.getParameter("to");
        double amount = Double.parseDouble(req.getParameter("amount"));
        accountService.transfer(currentUser(req), to, amount);
    }
}
```

### 安全代码（Java Servlet，校验 CSRF Token）

```java
@WebServlet("/transfer")
public class TransferServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        HttpSession session = req.getSession();
        String expected = (String) session.getAttribute("csrf_token");
        String actual = req.getParameter("csrf_token");
        if (expected == null || !expected.equals(actual)) {
            resp.sendError(403, "CSRF Token 校验失败");
            return;
        }
        String to = req.getParameter("to");
        double amount = Double.parseDouble(req.getParameter("amount"));
        accountService.transfer(currentUser(req), to, amount);
    }
}
```

## 参考资料

- CWE-352: https://cwe.mitre.org/data/definitions/352.html
- OWASP CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
