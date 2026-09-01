# XXE（XML 外部实体注入）

> CWE-611: Improper Restriction of XML External Entity Reference
> OWASP A05:2021 - Security Misconfiguration

## 漏洞描述

XXE（XML External Entity）发生在应用程序解析 XML 时允许外部实体引用，
攻击者可通过自定义 DOCTYPE 声明读取本地文件、发起内网请求
（SSRF）或造成拒绝服务（Billion Laughs）。

典型恶意 XML：

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

## 漏洞成因

1. XML 解析器使用默认配置，未禁用外部实体（DTD / 外部通用实体）；
2. 接收并解析不可信的 XML 数据（接口对接、文件上传、SOAP 等场景）；
3. 使用了不安全解析库的默认行为。

## 漏洞影响

- 任意文件读取（file:// 协议）；
- 内网探测与请求伪造（http:// 协议）；
- 实体扩展攻击导致拒绝服务（如 Billion Laughs）；
- 部分语言 / 场景可进一步实现 RCE。

## 检测方法

- 代码审计：检查 XML 解析器配置（`XMLReader`、`lxml`、`DocumentBuilderFactory`
  等是否显式禁用 DTD / 外部实体）；
- 动态测试：提交含外部实体的 XML，观察响应是否包含 `/etc/passwd`
  内容或内网请求特征；
- 扫描测试：提交实体扩展载荷观察是否拒绝服务。

## 修复方法

1. **禁用 DTD 与外部实体**：所有解析器显式设置
   `disallow-doctype-decl`、`external-general-entities=false`、
   `external-parameter-entities=false`；
2. 优先使用 JSON 等更安全的序列化格式，确需 XML 时限制 DOCTYPE；
3. 对 XML 输入做大小与嵌套深度限制，防实体扩展 DoS；
4. 升级解析库到安全版本。

## 代码示例

### 漏洞代码（Java）

```java
import javax.xml.parsers.DocumentBuilderFactory;

DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
// 默认配置：未禁用 DTD / 外部实体
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(inputStream);   // 可被 XXE 利用
```

### 安全代码（Java）

```java
import javax.xml.parsers.DocumentBuilderFactory;

DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setExpandEntityReferences(false);
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(inputStream);
```

### 漏洞代码（Python lxml）

```python
from lxml import etree

# 默认允许外部实体
root = etree.parse(xml_source)
```

### 安全代码（Python lxml）

```python
from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    load_dtd=False,
)
root = etree.parse(xml_source, parser=parser)
```

## 参考资料

- CWE-611: https://cwe.mitre.org/data/definitions/611.html
- OWASP XXE Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
