# 后端镜像：AI 代码安全审计系统
FROM python:3.10-slim

WORKDIR /app

# 系统依赖（semgrep 可选；当前不需要编译型依赖）
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# 复制后端代码
COPY backend/app /app/app

# 数据目录（知识库原始数据 / 处理产物 / 向量库）
COPY backend/data/raw /app/data/raw

EXPOSE 8000

# 启动（生产使用 gunicorn + uvicorn worker；简单起见直接 uvicorn）
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
