#!/usr/bin/env bash
# ============================================================================
# web-acceptance.sh — 控制台「真机逐页验收」（把 dev server 指到 k8s 后端，用真浏览器点一遍）
#
#   PODCLOUD_WEB_EMAIL=you@example.com PODCLOUD_WEB_PASSWORD='...' \
#     bash scripts/web-acceptance.sh
#
# 为什么需要它：i18n 的三类问题里有两类**静态检查永远看不见**——
#   · 压根没包 t() 的硬编码中文；
#   · 包了 t() 但键对不上（比如 Vue 模板会把 &gt; 解码成 >，词表存的是实体）；
# 再加上"页面根本没渲染出来"也会伪装成"没有中文"。所以验收标准是两条：
# 渲染出内容 + 无非数据中文。规则见 docs/PUBLISHING.md。
#
# 环境变量：
#   PODCLOUD_WEB_EMAIL / PODCLOUD_WEB_PASSWORD   登录用（必需，二选一：或给 TOKEN）
#   PODCLOUD_WEB_TOKEN                          直接注入 token，跳过登录界面（CI 用）
#   PODCLOUD_LOCALE                             断言哪个语言，默认 en-US
#   WEB_PORT / API_PORT                         默认 15199 / 8000
#   K8S_NS / K8S_SVC                            默认 podcloud / podcloud-server
#   SKIP_FORWARD=1 / SKIP_DEV=1                 复用已有的端口转发 / dev server
#   CHROME                                      默认 macOS 的 Google Chrome 路径
# ============================================================================
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

WEB_PORT="${WEB_PORT:-15199}"
API_PORT="${API_PORT:-8000}"
K8S_NS="${K8S_NS:-podcloud}"
K8S_SVC="${K8S_SVC:-podcloud-server}"
LOCALE="${PODCLOUD_LOCALE:-en-US}"
MIN_LINES="${MIN_LINES:-4}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'
ok()  { echo -e "  ${GREEN}✅${NC} $*"; }
bad() { echo -e "  ${RED}❌${NC} $*"; }
warn(){ echo -e "  ${YELLOW}⚠️${NC}  $*"; }

if [ -z "${PODCLOUD_WEB_TOKEN:-}" ] && { [ -z "${PODCLOUD_WEB_EMAIL:-}" ] || [ -z "${PODCLOUD_WEB_PASSWORD:-}" ]; }; then
  bad "缺少登录凭据。用法："
  echo "     PODCLOUD_WEB_EMAIL=you@example.com PODCLOUD_WEB_PASSWORD='...' bash scripts/web-acceptance.sh"
  echo "  或用已有的 access token（跳过登录界面）："
  echo "     PODCLOUD_WEB_TOKEN='eyJ...' bash scripts/web-acceptance.sh"
  exit 1
fi

FORWARD_PID=""
DEV_PID=""
cleanup() {
  # npm run dev 会再 fork 一个 vite 子进程，按 PID 杀不够，按端口兜底
  if [ -n "$DEV_PID" ] || lsof -ti ":$WEB_PORT" >/dev/null 2>&1; then
    kill "$DEV_PID" 2>/dev/null
    pkill -f "vite --port $WEB_PORT" 2>/dev/null
    warn "已停 dev server"
  fi
  if [ -n "$FORWARD_PID" ]; then
    kill "$FORWARD_PID" 2>/dev/null && warn "已停端口转发（${API_PORT}）"
  fi
}
trap cleanup EXIT INT TERM

echo "── 1. 后端（k8s ${K8S_NS}/${K8S_SVC} → 127.0.0.1:${API_PORT}）"
if [ "${SKIP_FORWARD:-0}" = "1" ]; then
  warn "SKIP_FORWARD=1，复用已有转发"
elif ! kubectl -n "$K8S_NS" get svc "$K8S_SVC" >/dev/null 2>&1; then
  bad "集群里找不到 svc/$K8S_SVC（namespace=$K8S_NS）。先跑 cloud/server/deploy/k8s/install-local.sh"
  exit 1
else
  kubectl -n "$K8S_NS" port-forward "svc/$K8S_SVC" "$API_PORT:8000" >/tmp/pod-web-accept-forward.log 2>&1 &
  FORWARD_PID=$!
  for _ in $(seq 1 30); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$API_PORT/api/v1/auth/config" || true)
    [ "$code" = "200" ] && break
    sleep 0.5
  done
  if [ "${code:-}" = "200" ]; then ok "后端就绪（/api/v1/auth/config 200）"; else bad "后端没起来，见 /tmp/pod-web-accept-forward.log"; exit 1; fi
fi

echo "── 2. 前端 dev server（127.0.0.1:${WEB_PORT}，代理 /api → ${API_PORT}）"
if [ "${SKIP_DEV:-0}" = "1" ]; then
  warn "SKIP_DEV=1，复用已有 dev server"
else
  ( cd cloud/web && npm run dev -- --port "$WEB_PORT" --host 127.0.0.1 >/tmp/pod-web-accept-dev.log 2>&1 ) &
  DEV_PID=$!
  for _ in $(seq 1 40); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$WEB_PORT/" || true)
    [ "$code" = "200" ] && break
    sleep 0.5
  done
  if [ "${code:-}" = "200" ]; then ok "dev server 就绪"; else bad "dev server 没起来，见 /tmp/pod-web-accept-dev.log"; exit 1; fi
fi

echo "── 3. 真机逐页验收"
node scripts/web-acceptance.mjs \
  --base "http://127.0.0.1:$WEB_PORT" \
  --email "${PODCLOUD_WEB_EMAIL:-}" \
  --password "${PODCLOUD_WEB_PASSWORD:-}" \
  --token "${PODCLOUD_WEB_TOKEN:-}" \
  --locale "$LOCALE" \
  --min-lines "$MIN_LINES" \
  ${CHROME:+--chrome "$CHROME"}
RC=$?

echo
if [ "$RC" = "0" ]; then ok "验收通过"; else bad "验收未通过（退出码 ${RC}）"; fi
exit "$RC"
