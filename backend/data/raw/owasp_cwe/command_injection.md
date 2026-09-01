# 命令注入（Command Injection）

> CWE-78: Improper Neutralization of Special Elements used in an OS Command
> OWASP A03:2021 - Injection

## 漏洞描述

命令注入发生在应用程序将不可信输入拼接到操作系统命令中并执行时，
攻击者可注入额外的命令或在命令中插入特殊字符，实现任意命令执行。

常见注入点：

```text
127.0.0.1; cat /etc/passwd
127.0.0.1 && whoami
127.0.0.1 | id
$(whoami)
`whoami`
```

## 漏洞成因

1. 业务需要调用系统命令（ping、tar、convert 等），输入直接拼接；
2. 使用 `os.system`、`Runtime.exec`、`subprocess(shell=True)` 等
   shell 解释执行接口；
3. 未使用参数列表方式调用外部程序。

## 漏洞影响

- 任意命令执行，通常以应用进程权限运行；
- 读取 / 篡改文件、安装后门、横向移动；
- 在容器或低权限环境中也能造成数据泄露与业务破坏。

## 检测方法

- 代码审计：搜索调用系统命令的代码，检查参数是否经过净化；
- 静态扫描：Semgrep 可检测 `subprocess`、`os.system`、`Runtime.getRuntime().exec`
  等敏感调用与拼接模式；
- 动态测试：注入 `;`、`&&`、`|`、`$()`、反引号等元字符，
  观察响应或延时差异。

## 修复方法

1. **避免调用系统命令**：优先使用语言原生库实现等价功能
   （如 Python `shutil`、Java 标准库）；
2. 必须调用时，使用参数列表形式（`subprocess.run([...], shell=False)`、
   `ProcessBuilder`），不使用 shell 解释；
3. 对输入做白名单校验（如 IP 格式、主机名字符集）；
4. 最小权限运行应用进程。

## 代码示例

### 漏洞代码（Python）

```python
import subprocess

ip = request.args.get("ip")
# shell=True + 字符串拼接 -> 命令注入
result = subprocess.run(f"ping -c 3 {ip}", shell=True, capture_output=True)
return result.stdout
```

### 安全代码（Python）

```python
import ipaddress
import subprocess

ip = request.args.get("ip")
# 白名单校验 IP 格式
ipaddress.ip_address(ip)            # 非法格式直接抛异常
# 参数列表方式，不经过 shell
result = subprocess.run(
    ["ping", "-c", "3", ip], capture_output=True, shell=False
)
return result.stdout
```

### 漏洞代码（Java）

```java
String ip = request.getParameter("ip");
Process p = Runtime.getRuntime().exec("ping -c 3 " + ip);
```

### 安全代码（Java）

```java
String ip = request.getParameter("ip");
// 校验 IP 格式后，使用参数数组，不经过 shell
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "3", ip);
Process p = pb.start();
```

## 参考资料

- CWE-78: https://cwe.mitre.org/data/definitions/78.html
- OWASP Command Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection.html
