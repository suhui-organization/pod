#!/usr/bin/env bash
# 把当前构建产物同步到海外静态镜像站。
#
#   HOST=1.2.3.4 SSH_KEY=~/.ssh/id_aliyun_prod bash deploy-static.sh
#
# 只做两件事：rsync 产物 + reload nginx。不做任何写配置的动作 ——
# 配置（nginx/证书）是首次装机时一次性建好的，见同目录 README。
set -euo pipefail

HOST="${HOST:?用法: HOST=<海外机器IP> [SSH_KEY=...] bash deploy-static.sh}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_aliyun_prod}"
SSH_USER="${SSH_USER:-root}"
REMOTE_DIR="${REMOTE_DIR:-/var/www/podcloud}"

REPO_WEB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_WEB_DIR"

echo "==> 构建前端产物"
npm run build

echo "==> 校验产物里有公开页要用的东西"
test -f dist/index.html || { echo "dist/index.html 不存在，构建失败？" >&2; exit 1; }

echo "==> 同步到 $SSH_USER@$HOST:$REMOTE_DIR"
rsync -az --delete -e "ssh -i $SSH_KEY -o BatchMode=yes" \
  dist/ "$SSH_USER@$HOST:$REMOTE_DIR/"

echo "==> reload nginx"
ssh -i "$SSH_KEY" -o BatchMode=yes "$SSH_USER@$HOST" \
  'nginx -t && systemctl reload nginx && echo nginx reloaded'

echo "==> 从境外视角自检（可选：本机装了 curl 就能跑）"
for p in / /product /pricing /legal/terms /legal/refund /legal/privacy; do
  printf '%-18s ' "$p"
  curl -sS -o /dev/null -w '%{http_code}\n' --max-time 15 "https://podcloud.dlszjr.com$p" || echo '(取不到)'
done
