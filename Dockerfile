# zcode2api Dockerfile
# Python 3.12 + Node.js 20 + Chromium 同镜像:FastAPI 网关 + captcha_node 验证码求解子进程
FROM python:3.12-slim

# 安装 Node.js 20(给 captcha_node 用)+ Chromium(验证码求解器 solver_pw.js 需要真浏览器)
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs chromium \
    && rm -rf /var/lib/apt/lists/*
ENV ZCODE_CHROMIUM_PATH=/usr/bin/chromium

WORKDIR /app

# Python 依赖
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# captcha_node 依赖(npm install 只需跑一次,打进镜像)
COPY captcha_node/package.json captcha_node/package-lock.json* ./captcha_node/
RUN cd captcha_node && npm install --omit=dev && npm cache clean --force

# 应用代码
COPY . .

# 平台默认注入 PORT=8080,这里让网关监听 8080;
# /data 挂 Volume 做 SQLite 持久化(重部署/重启不丢账号)
ENV ZCODE_HOST=0.0.0.0 \
    ZCODE_PORT=8080 \
    ZCODE_DATA_DIR=/data

VOLUME /data
EXPOSE 8080

# ZCODE_ADMIN_KEY / ZCODE_GATEWAY_KEY 等密钥不要写进镜像,
# 在 Northflank Dashboard -> Variables 里设置
CMD ["python", "cli.py", "serve"]
