# OWASP Top 10 (2021) 概览

> 来源：OWASP Top 10 2021（原创整理，供检索定位）

## 简介

OWASP Top 10 是 OWASP 基金会发布的 Web 应用十大安全风险清单，
用于指导开发与审计。2021 版按可被利用性、检测难度与影响加权排序。

## Top 10 列表

1. A01:2021 Broken Access Control（访问控制失效）
2. A02:2021 Cryptographic Failures（加密机制失效）
3. A03:2021 Injection（注入）
4. A04:2021 Insecure Design（不安全设计）
5. A05:2021 Security Misconfiguration（安全配置错误）
6. A06:2021 Vulnerable and Outdated Components（易受攻击和过时的组件）
7. A07:2021 Identification and Authentication Failures（身份识别和认证失效）
8. A08:2021 Software and Data Integrity Failures（软件和数据完整性故障）
9. A09:2021 Security Logging and Monitoring Failures（安全日志和监控失败）
10. A10:2021 Server-Side Request Forgery（服务端请求伪造）

## 与常见 CWE 的对应关系

- A01:2021 常对应 CWE-22（路径遍历）、CWE-352（CSRF）、CWE-862（越权）
- A02:2021 常对应 CWE-319（明文传输）、CWE-326（弱加密）
- A03:2021 常对应 CWE-79（XSS）、CWE-89（SQL 注入）、CWE-78（命令注入）
- A07:2021 常对应 CWE-287（认证缺陷）、CWE-306（缺失认证）
- A08:2021 常对应 CWE-502（不安全反序列化）
- A10:2021 对应 CWE-918（SSRF）

## 使用建议

知识检索时，可先用 OWASP 分类（如 A03:2021）定位风险大类，
再结合 CWE 编号定位具体缺陷类型，最后对照漏洞描述 / 检测 / 修复
章节生成审计结论。
