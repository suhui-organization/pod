# Pod Cloud 后端镜像
# 构建: docker build -f deploy/Dockerfile -t podcloud-server:<tag> .
FROM python:3.12-slim

# 本次构建的标识（镜像 tag），由 install-local.sh / install-server.sh 用
# --build-arg BUILD_TAG=... 注入；app/config.py 读 PODCLOUD_BUILD_TAG，
# 再经 /api/v1/auth/config 暴露给界面与运维。
ARG BUILD_TAG=dev
ENV PODCLOUD_BUILD_TAG=$BUILD_TAG

# 本次构建来自哪个 commit。tag 是每镜像独立的内容指纹，"前后端是不是同一次发布"
# 只能按 commit 判断（前端拿自己的 commit 与 /auth/config 的 build_commit 对照）。
ARG BUILD_COMMIT=
ENV PODCLOUD_BUILD_COMMIT=$BUILD_COMMIT

WORKDIR /app
ENV PYTHONPATH=/app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple -r /app/requirements.txt

COPY app /app/app
COPY scripts /app/scripts

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
