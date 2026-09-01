# PROJECT_ARCHITECTURE

项目架构说明。总体架构遵循项目根目录《毕设设计路线.md》，本文档描述
已落地代码的结构与设计决策。

## 1. 总体架构

```text
Vue3 前端（Element Plus）
   │ HTTP /api
   ▼
FastAPI 后端
   │
   ├── 认证层（JWT + bcrypt）
   ├── 项目/审计 API（上传 zip -> 解压 -> 扫描 -> Agent 审计 -> 落库）
   │
   ├── Multi-Agent 协同层
   │   Orchestrator → Audit / Knowledge / Repair / Report Agent
   │        │              │
   │        ▼              ▼
   │   静态扫描工具      RAG 知识库
   │   Bandit/Semgrep/AST  ChromaDB + Embedding + Retriever
   │        │              │
   │        ▼              ▼
   │        └──── LLM（DeepSeek 等，可替换）────┘
   │
   ├── MySQL / SQLite（SQLAlchemy 双兼容）
   └── Agent 执行日志（文件 JSONL + 数据库表）
```

## 2. 模块清单（按毕设路线对应）

| 毕设路线章节 | 模块 | 实现位置 | 状态 |
|---|---|---|---|
| 13 文档加载 | loader | `app/rag/loader/`（5 格式 + 注册表） | ✅ |
| 14 文本清洗 | cleaner | `app/rag/cleaner.py` | ✅ |
| 15-16 文本分割 | splitter | `app/rag/splitter.py` | ✅ |
| 17 Metadata | metadata | `app/rag/metadata.py` | ✅ |
| 18 Embedding | embedding | `app/rag/embedding.py`（BGE-M3/Hashing） | ✅ |
| 19 ChromaDB | vector_store | `app/rag/vector_store.py` | ✅ |
| 20 检索策略 | retriever + reranker | `app/rag/retriever.py` / `reranker.py` | ✅ |
| 21 安全扫描 | scanner + ast_analyzer | `app/security/` | ✅ |
| 22 工具+LLM协同 | detector + audit_agent | `app/security/detector.py` / `app/agents/audit_agent.py` | ✅ |
| 6-10 Multi-Agent | agents | `app/agents/` | ✅ |
| 25 数据库 | models | `app/models/`（8 张表） | ✅ |
| 26 Agent日志 | agent_log | `app/agents/agent_log.py` + `models/agent_log.py` | ✅ |
| 5 后端 | api + main | `app/api/` + `app/main.py` | ✅ |
| 4 前端 | frontend | `frontend/`（Vue3 + Element Plus） | ✅ |
| Docker | 部署 | `docker-compose.yml` + 双 Dockerfile | ✅ |

## 3. 关键设计决策

### 3.1 审计流水线（静态 → Agent → LLM → RAG）

```text
上传 zip → ProjectParser（防 Zip Slip 解压、语言识别）
→ VulnerabilityDetector（Bandit + Semgrep[可选] + AST，去重）
→ Orchestrator.run_audit：
    AuditAgent（每条发现：RAG 检索知识 → LLM 综合判断 → 确认漏洞）
    → RepairAgent（生成修复建议/Patch，不直接改源码）
    → ReportAgent（安全评分 100 起扣、漏洞明细、总体评价）
→ 落库（task/vulns/suggestions/agent_logs/report）
```

### 3.2 ChromaDB 过滤语义的适配

ChromaDB 1.x 的 `where` 过滤对数组字段不支持"包含"语义（实测 `$in` 精确匹配标量、
`$contains` 仅对文档内容有效）。因此：
- 入库时列表型 metadata（cwe_id 等）序列化为 `"; "` 分隔字符串（保留完整信息）；
- CWE 编号检索用 `where_document $contains`（安全知识正文均标注 CWE 编号）；
- 标量字段（category/source）用 `$in`/`$eq` 精确过滤。

### 3.3 LLM / Embedding / 扫描器可替换性

| 组件 | 抽象接口 | 实现 | 切换方式 |
|---|---|---|---|
| LLM | `LLMClient.chat()` | OpenAICompatibleLLM（DeepSeek/Qwen）/ MockLLM | `.env` LLM_API_KEY |
| Embedding | `EmbeddingProvider.embed_texts()` | BgeM3 / Hashing | `.env` EMBEDDING_PROVIDER |
| 扫描器 | `BaseScanner.scan()` | Bandit / Semgrep / AST | 注册列表 + available() |

无 API Key / 无模型 / 无 semgrep 时系统自动降级，不阻断流程（毕业设计答辩演示友好）。

### 3.4 数据库双兼容

- SQLite：本地开发与测试（`backend/data/app.db`，测试用独立库）；
- MySQL：生产部署（`docker-compose` 提供 mysql:8.0 服务）；
- 全部 ORM 使用 SQLAlchemy 方言无关写法，切换仅需改 `.env`。

### 3.5 安全设计

- 上传 zip 防路径穿越（拒绝 `..` / 绝对路径 / 危险根目录，单一根目录自动展开）；
- JWT 认证（bcrypt 密码哈希 + PyJWT 签名，过期校验）；
- 任务/项目归属校验（用户只能访问自己的数据）；
- 修复 Agent 只输出建议，`apply_to_source=False`，不直接修改原始代码。

## 4. 前端页面与接口对应

| 页面 | 路由 | 后端接口 |
|---|---|---|
| 登录/注册 | /login | /api/auth/* |
| 项目管理 | /projects | /api/projects |
| 项目详情（上传+审计） | /projects/:id | /api/projects/:id/upload、/api/audit/tasks |
| 审计结果（漏洞列表/详情+修复） | /audit/:taskId | /api/vulnerabilities、/api/vulnerabilities/:id/suggestions |
| Agent 执行过程 | /agents/:taskId | /api/agents/tasks/:id/logs |
| 安全报告 | /report/:taskId | /api/reports/tasks/:id |
| RAG 知识检索 | /rag | /api/rag/* |
