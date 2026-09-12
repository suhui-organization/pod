#!/usr/bin/env bash
# FinHarness SaaS 后端启动脚本
set -euo pipefail
cd "$(dirname "$0")"
exec ../.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port "${FINHARNESS_PORT:-8000}"
