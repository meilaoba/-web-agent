# 不安全反序列化（Insecure Deserialization）

> CWE-502: Deserialization of Untrusted Data
> OWASP A08:2021 - Software and Data Integrity Failures

## 漏洞描述

不安全反序列化指应用程序反序列化不可信的、攻击者可控的数据，
攻击者构造恶意序列化数据触发代码执行、DoS 或数据篡改。

Java 原生反序列化（ObjectInputStream）、Python pickle、
PHP unserialize 等均为高风险入口，配合反序列化 gadget 链
可形成远程代码执行。

## 漏洞成因

1. 直接反序列化用户可控数据（Cookie、请求体、消息队列消息）；
2. 使用原生反序列化机制，而非限定类型的安全格式（JSON + 显式类）；
3. 依赖库中存在可利用的反序列化 gadget 链
   （如 Apache Commons Collections、fastjson 旧版本）。

## 漏洞影响

- 远程代码执行（最严重）；
- 拒绝服务（对象构造消耗资源）；
- 数据篡改与权限提升。

## 检测方法

- 代码审计：搜索 `ObjectInputStream.readObject`、`pickle.loads`、
  `unserialize` 等调用，检查数据来源是否可信；
- 依赖检查：扫描依赖中已知的反序列化 gadget 库版本；
- 动态测试：使用 ysoserial / 通用 gadget payload 验证是否存在可利用链。

## 修复方法

1. **避免反序列化不可信数据**：改用 JSON / Protobuf 等安全格式，
   并显式定义数据模型与校验；
2. 必须使用原生反序列化时：加白名单过滤（Java
   `ObjectInputFilter` / JEP 290，禁止反序列化非白名单类）；
3. 对反序列化输入做签名 / 加密（防止篡改）；
4. 升级存在 gadget 链风险的依赖库；
5. 最小权限运行应用，降低利用后的影响。

## 代码示例

### 漏洞代码（Java）

```java
import java.io.ObjectInputStream;

// 直接反序列化客户端提交的字节流
byte[] data = Base64.getDecoder().decode(request.getParameter("payload"));
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
Object obj = ois.readObject();   // 危险：可触发 gadget 链 RCE
```

### 安全代码（Java，类白名单过滤）

```java
import java.io.ObjectInputFilter;

byte[] data = Base64.getDecoder().decode(request.getParameter("payload"));
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
// 仅允许反序列化白名单内的业务类
ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
    "java.base/*;com.example.dto.*;!*"
));
Object obj = ois.readObject();
```

### 漏洞代码（Python pickle）

```python
import pickle

data = request.get_data()          # 用户可控
obj = pickle.loads(data)           # 危险：可执行任意代码
```

### 安全代码（Python，改用 JSON 并校验）

```python
import json

data = json.loads(request.get_data())
# 显式校验字段与类型
if not isinstance(data.get("user_id"), int):
    raise ValueError("非法数据")
```

## 参考资料

- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- OWASP Deserialization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
