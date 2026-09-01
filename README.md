# AI驱动的Web代码安全审计多Agent系统

基于 **LLM + Multi-Agent + RAG + 静态代码分析** 的智能 Web 代码安全审计系统（毕业设计项目）。

> 总体架构与开发路线详见 [`毕设设计路线.md`](../毕设设计路线.md)（项目根目录，勿修改）。

## 文档索引

| 文档 | 说明 |
|---|---|
| [`使用文档.md`](使用文档.md) | 使用指南：技术栈、框架结构、接口、核心函数说明 |

## 系统能力

```text
代码上传 → 项目解析 → 静态安全扫描（Bandit/Semgrep/AST）
→ Multi-Agent 协同审计（Orchestrator + Audit/Knowledge/Repair/Report Agent）
→ RAG 安全知识检索 → 漏洞综合判断 → 风险评级 → 修复建议 → 安全报告
→ 前端可视化展示（Vue3）
```

三大核心能力：

1. **AI能力**：LLM（DeepSeek 等可替换）+ Multi-Agent 协同 + Agent 执行日志
2. **知识能力**：RAG（文档加载/清洗/分割 → Embedding → ChromaDB → Retriever → Reranker）
3. **安全能力**：静态扫描（Bandit / Semgrep / AST）+ 漏洞检测 + 修复建议生成

## 目录结构

```text
backend/
├── app/
│   ├── config.py                 # 配置管理（.env + 环境变量，与代码分离）
│   ├── main.py                   # FastAPI 应用入口
│   ├── api/                      # REST API（auth/projects/audit/vulnerabilities/rag/agents/reports）
│   ├── models/                   # SQLAlchemy ORM（users/projects/audit_tasks/files/
│   │                             #   vulnerabilities/repair_suggestions/audit_reports/agent_logs）
│   ├── schemas/                  # Pydantic 请求/响应模型
│   ├── services/                 # 业务服务（数据库/认证/审计编排）
│   ├── rag/                      # RAG 模块
│   │   ├── loader/               #   文档加载（md/txt/json/html/pdf，注册表分发）
│   │   ├── cleaner.py            #   文本清洗（代码块保护，保留安全知识）
│   │   ├── splitter.py           #   语义感知文本分割（标题/代码块感知 + token 估算）
│   │   ├── metadata.py           #   CWE/CVE/OWASP 提取与规范化
│   │   ├── embedding.py          #   Embedding（BGE-M3 / Hashing 可替换）
│   │   ├── vector_store.py       #   ChromaDB 向量存储
│   │   ├── retriever.py          #   检索器（向量检索 + Metadata 过滤 + Top-K）
│   │   └── reranker.py           #   重排序（关键词 + 向量加权）
│   ├── security/                 # 安全分析模块
│   │   ├── project_parser.py     #   项目上传/解压（防 Zip Slip）/语言识别
│   │   ├── scanner.py            #   Bandit / Semgrep 扫描器（可插拔）
│   │   ├── ast_analyzer.py       #   Python AST 危险模式分析
│   │   ├── detector.py           #   多扫描器汇总去重
│   │   └── models.py             #   扫描结果数据模型
│   └── agents/                   # Multi-Agent 模块
│       ├── llm.py                #   LLM 客户端（DeepSeek OpenAI 兼容 / Mock）
│       ├── base.py               #   Agent 基类与任务上下文
│       ├── orchestrator.py       #   主 Agent（任务编排）
│       ├── audit_agent.py        #   审计 Agent（静态+知识+LLM 综合判断）
│       ├── knowledge_agent.py    #   知识 Agent（RAG 检索）
│       ├── repair_agent.py       #   修复 Agent（修复建议，不直接改源码）
│       ├── report_agent.py       #   报告 Agent（安全评分/报告）
│       └── agent_log.py          #   Agent 执行日志（执行链）
├── data/
│   ├── raw/                      # 原始知识数据（OWASP/CWE 10 类漏洞等）
│   └── processed/                # 处理产物（chunks.jsonl + summary.json）
├── tests/                        # pytest 测试（95+ 用例）
├── requirements.txt
└── Dockerfile
frontend/                         # Vue3 + Vite + Element Plus
├── src/views/                    # 登录/项目管理/代码上传/审计结果/Agent过程/报告/RAG检索
└── Dockerfile + nginx.conf
scripts/                          # 按作用分类的脚本
├── data_pipeline/                #   知识库数据处理（构建/入库/样例/管线）
├── retrieval/                    #   RAG 检索与效果评估
├── launch/                       #   服务启动与一键脚本
└── dev_tools/                    #   测试与开发辅助工具
docker-compose.yml                # mysql + backend + frontend 部署
```

## 快速开始

### 1. 后端

```bash
pip install -r backend/requirements.txt
python scripts/data_pipeline/init_knowledge.cmd        # 构建知识库并向量入库（可选，启用 RAG）
python scripts/launch/run_backend.cmd                  # 启动 API（http://127.0.0.1:8000/docs）
```

未配置 `LLM_API_KEY` 时自动使用 MockLLM（离线可完整演示 Multi-Agent 流程）；
配置 `.env` 中的 `LLM_PROVIDER` / `LLM_API_KEY` 后使用真实模型
（qwen / deepseek / openai / ollama 等，详见 `.env.example`）。

### 2. 前端

```bash
cd frontend
npm install
npm run dev            # http://127.0.0.1:5173（已配置 /api 代理到 8000）
npm run build          # 生产构建
```

### 2.1 一键启动全部服务（推荐）

```bash
scripts\launch\start_all.cmd
# 自动：检查依赖 → 首次自动安装前端依赖 → 首次自动初始化知识库
#       → 新窗口启动后端(8000) + 前端(5173)
# 可选参数：--skip-kb-init（跳过知识库初始化） / --dry-run（只打印步骤）
```

关闭对应的服务窗口即可停止服务。

### 3. 测试

```bash
cd backend && python -m pytest tests -v    # 全量测试
python scripts/dev_tools/smoke_test.py     # 对运行中的后端做冒烟验证
```

### 4. Docker 部署（MySQL + 后端 + 前端）

```bash
docker compose up -d --build
# 前端 http://localhost，API 文档 http://localhost:8000/docs
```

## 关键设计说明

- **静态工具 → Agent → LLM → RAG** 分层协同：Bandit/Semgrep/AST 发现可疑代码，
  Audit Agent 结合 RAG 知识与 LLM 综合判断，避免纯 LLM 幻觉与纯工具误报；
- **组件可替换**：LLM（OpenAI 兼容）、Embedding（BGE-M3/Hashing）、向量库（ChromaDB）、
  扫描器（Bandit/Semgrep/AST）均通过抽象接口 + 配置切换；
- **数据库双兼容**：SQLAlchemy 支持 MySQL（生产）与 SQLite（本地开发/测试）；
- **安全设计**：上传 zip 防路径穿越、JWT 认证、任务归属校验、修复 Agent 不直接改源码；
- **可演示性**：Agent 执行链日志落盘 + 入库，前端完整展示"审计→知识→修复→报告"全过程。

## 后续待办

- [ ] 审计任务异步化（Celery/后台任务）
- [ ] RAG Reranker 升级为 BGE-Reranker / Cross-Encoder
- [ ] 前端审计过程实时推送（WebSocket/SSE）
- [ ] 漏洞修复 Patch 一键应用（用户确认后）
- [ ] 论文实验（Chunk 参数 / Top-K / RAG 有效性 / Multi-Agent 有效性）
