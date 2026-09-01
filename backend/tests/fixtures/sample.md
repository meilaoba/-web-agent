# 测试用 Markdown 样例：SQL 注入

> CWE-89
> OWASP A03:2021

## 漏洞描述

本文件用于单元测试，验证 Markdown 加载与文本分割。

SQL 注入发生在用户输入被拼接到 SQL 查询中时。

## 代码示例

### 漏洞代码（Java）

```java
String sql = "SELECT * FROM users WHERE id=" + id;
```

### 安全代码（Java）

```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id=?");
ps.setString(1, id);
```

## 修复方法

使用参数化查询，禁止字符串拼接 SQL。

## 参考资料

- CWE-89: https://cwe.mitre.org/data/definitions/89.html
