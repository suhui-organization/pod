# Pod Cloud 后端镜像
# 构建: docker build -f deploy/Dockerfile -t podcloud-server:<tag> .
FROM python:3.12-slim

# 本次构建的标识（镜像 tag），由 install-local.sh / install-server.sh 用
# --build-arg BUILD_TAG=... 注入；app/config.py 读 PODCLOUD_BUILD_TAG，
# 再经 /api/v1/auth/config 暴露给界面与运维。
ARG BUILD_TAG=dev
ENV PODCLOUD_BUILD_TAG=$BUILD_TAG

WORKDIR /app
ENV PYTHONPATH=/app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple -r /app/requirements.txt

COPY app /app/app
COPY scripts /app/scripts

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
