#!/usr/bin/env bash
# Pod Cloud 后端本地启动脚本（开发用；生产见仓库 deploy/）
set -euo pipefail
cd "$(dirname "$0")"
PYTHON_BIN="${PYTHON_BIN:-.venv/bin/python}"
exec "${PYTHON_BIN}" -m uvicorn app.main:app --host 0.0.0.0 --port "${PODCLOUD_PORT:-8000}"
