# SQL 注入（SQL Injection）

> CWE-89: Improper Neutralization of Special Elements used in an SQL Command
> OWASP A03:2021 - Injection

## 漏洞描述

SQL 注入发生在应用程序将不可信的用户输入直接拼接到 SQL 查询语句中，
导致攻击者可以修改查询语义、绕过认证、读取或篡改数据库中的任意数据。

典型的拼接方式：

```java
String sql = "SELECT * FROM users WHERE id=" + id;
```

当 `id` 来自用户输入时，攻击者传入 `1 OR 1=1` 即可让查询返回全部用户记录。

## 漏洞成因

1. 使用字符串拼接或格式化方式构造 SQL，而不是使用参数化查询；
2. 缺少对输入数据与 SQL 语句结构的边界区分；
3. 数据库账户使用过高权限，放大了注入攻击的影响范围。

## 漏洞影响

- 数据泄露：读取数据库中的敏感信息；
- 数据篡改 / 删除：破坏数据完整性；
- 认证绕过：例如 `' OR '1'='1` 绕过登录校验；
- 在部分数据库（如 MySQL 结合堆叠查询）下可进一步执行命令。

## 检测方法

- 代码审计：搜索 SQL 字符串拼接模式（`+`、`concat`、`format` 拼接 SQL）；
- 静态扫描：使用 Semgrep / Bandit 等规则检测拼接点；
- 动态测试：在输入点注入 `'`、`1' OR '1'='1`、`1 AND 1=2` 等测试载荷，
  观察响应差异（错误信息、布尔差异、时间差异）。

## 修复方法

1. 首选**参数化查询 / PreparedStatement**，将数据与 SQL 结构分离；
2. 无法参数化时，使用白名单校验与严格转义，并配合输入校验；
3. 最小权限原则：数据库账户只授予必要权限；
4. 隐藏数据库错误详情，避免注入探测信息泄露。

## 代码示例

### 漏洞代码（Java）

```java
String id = request.getParameter("id");
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id=" + id);
```

### 安全代码（Java）

```java
String id = request.getParameter("id");
PreparedStatement ps = connection.prepareStatement(
    "SELECT * FROM users WHERE id=?");
ps.setString(1, id);
ResultSet rs = ps.executeQuery();
```

### 漏洞代码（Python）

```python
import sqlite3

user_input = request.args.get("id")
conn = sqlite3.connect("app.db")
cursor = conn.execute(f"SELECT * FROM users WHERE id={user_input}")
```

### 安全代码（Python）

```python
import sqlite3

user_input = request.args.get("id")
conn = sqlite3.connect("app.db")
cursor = conn.execute("SELECT * FROM users WHERE id=?", (user_input,))
```

## 参考资料

- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- OWASP Injection: https://owasp.org/www-project-top-ten/
