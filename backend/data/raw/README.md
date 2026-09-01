# 安全知识库原始数据说明

本目录保存 RAG 知识库的**原始数据**（Phase 1 测试知识库）。

## 目录结构

```text
data/raw/
├── owasp_cwe/           # 按漏洞类型组织的 OWASP / CWE 知识文档（Markdown）
├── owasp_top10/         # OWASP Top 10 概览
├── quick_reference/     # 多格式样例（txt / json / html / pdf），验证加载器
└── README.md
```

## 数据来源与版权说明

- 全部文档为**依据 OWASP / CWE 公开通用知识撰写的原创整理文本**，
  不包含大段受版权保护的原文复制。
- 每个文档标注 CWE 编号与 OWASP 引用，便于后续来源追踪。
- 后续阶段将补充 CVE、Web 安全案例、安全开发规范、漏洞技术文档等，
  新增数据同样要求保留来源信息。

## 处理产物

处理后的 Chunk 数据输出到 `data/processed/`（由
`scripts/build_knowledge_base.py` 生成，不纳入版本管理）。
