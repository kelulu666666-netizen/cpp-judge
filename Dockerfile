FROM python:3.11-slim

# 安装 g++ 与编译依赖
RUN apt-get update \
    && apt-get install -y --no-install-recommends g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py index.html admin.html ./

# 暴露端口（容器运行时用 -p 映射到宿主机）
ENV PORT=8000
EXPOSE 8000

# 运行时请用 --cap-drop=ALL --security-opt=no-new-privileges --read-only 进一步加固
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT}"]
