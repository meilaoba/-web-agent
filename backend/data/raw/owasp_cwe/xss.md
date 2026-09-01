# 跨站脚本（XSS）

> CWE-79: Improper Neutralization of Input During Web Page Generation
> OWASP A03:2021 - Injection

## 漏洞描述

跨站脚本漏洞（Cross-Site Scripting，XSS）发生在应用程序将不可信输入
未经过滤或转义就输出到网页中，攻击者注入的脚本会在受害者的浏览器中执行。

按触发位置分为三类：

- 反射型 XSS：注入内容通过请求参数回显，需诱导用户点击恶意链接；
- 存储型 XSS：注入内容持久化到服务端（数据库），任何访问页面的人都会触发；
- DOM 型 XSS：漏洞存在于前端 JavaScript 对 DOM 的操作中，不经过服务端。

## 漏洞成因

1. 用户输入直接拼接进 HTML / JavaScript / URL 输出，未做上下文感知转义；
2. 前端使用 `innerHTML`、`document.write`、`eval` 等危险 API 处理不可信数据；
3. 富文本场景只做了黑名单过滤，可被编码绕过。

## 漏洞影响

- 窃取 Cookie / Session，劫持用户会话；
- 钓鱼与恶意跳转；
- 键盘记录、内网探测等恶意行为；
- 配合 CSRF 可执行任意业务操作。

## 检测方法

- 代码审计：检查输出点是否转义（模板引擎 autoescape 是否开启）；
- 前端代码审查：搜索 `innerHTML`、`eval`、`document.write` 等危险 API；
- 动态测试：注入 `<script>alert(1)</script>`、`<img src=x onerror=alert(1)>`、
  `javascript:alert(1)` 等载荷，观察是否执行。

## 修复方法

1. 输出编码：按输出上下文（HTML / 属性 / JavaScript / URL）选择对应转义函数；
2. 输入校验：对允许的字符集做白名单校验，如仅允许字母数字；
3. 前端避免使用 `innerHTML` 等危险 API，改用 `textContent` 或框架转义机制；
4. 设置 `Content-Security-Policy` 响应头作为纵深防御；
5. 关键 Cookie 设置 `HttpOnly` 与 `SameSite` 属性。

## 代码示例

### 漏洞代码（Java JSP）

```jsp
<%
    String name = request.getParameter("name");
%>
<p>Hello, <%= name %></p>
```

### 安全代码（Java JSP，使用上下文转义）

```jsp
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%
    String name = request.getParameter("name");
%>
<p>Hello, ${fn:escapeXml(name)}</p>
```

### 漏洞代码（Python Flask 模板）

```html
<!-- 模板中直接输出用户输入 -->
<p>Hello, {{ name | safe }}</p>
```

### 安全代码（Python Flask 模板）

```html
<!-- 默认转义，不添加 safe 过滤器 -->
<p>Hello, {{ name }}</p>
```

## 参考资料

- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
