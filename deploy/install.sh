#!/usr/bin/env bash
# ============================================================================
# Pod Cloud 一键部署（单机 Docker Compose）
#
#   bash deploy/install.sh
#
# 做了什么：预检 docker → 生成 .env（缺密钥就生成）→ 构建镜像 → 起服务
#          → 等健康检查通过 → 打印访问地址与"下一步"
#
# 环境变量（都可不填）：
#   WEB_PORT            对外端口（默认 18088）
#   ADMIN_EMAIL         填了就顺手建管理员（否则在页面自助注册）
#   ADMIN_PASSWORD      与 ADMIN_EMAIL 成对
#   PUBLIC_BASE_URL     对外地址（默认 http://127.0.0.1:$WEB_PORT）
#   PODCLOUD_IS_PRIVATE true = 关闭公开注册
# ============================================================================
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DEPLOY_DIR"

WEB_PORT="${WEB_PORT:-18088}"
PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-http://127.0.0.1:$WEB_PORT}"
ADMIN_EMAIL="${ADMIN_EMAIL:-}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'
ok()  { echo -e "${GREEN}[ok]${NC}   $*"; }
warn(){ echo -e "${YELLOW}[warn]${NC} $*"; }
fail(){ echo -e "${RED}[fail]${NC} $*" >&2; exit 1; }
step(){ echo; echo -e "${GREEN}── $*${NC}"; }

step "0/5 预检"
command -v docker >/dev/null 2>&1 || fail "未找到 docker"
docker compose version >/dev/null 2>&1 || fail "需要 Docker Compose v2（docker compose，不是 docker-compose）"
docker info >/dev/null 2>&1 || fail "docker 守护进程没在跑"
[ -f ../cloud/server/app/main.py ] || fail "找不到 ../cloud/server —— 请在仓库根的 deploy/ 目录里执行"
ok "docker 与源码路径就绪"

step "1/5 生成配置"
if [ -f .env ]; then
  ok ".env 已存在（不覆盖你的配置）"
else
  cp .env.example .env
  SECRET="$(openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets;print(secrets.token_hex(32))')"
  # 就地替换空值（macOS 与 GNU sed 语法不同，这里用 python 保证一致）
  python3 - "$SECRET" "$WEB_PORT" "$PUBLIC_BASE_URL" "${PODCLOUD_IS_PRIVATE:-false}" <<'PY'
import re, sys
secret, port, base, private = sys.argv[1:5]
text = open('.env', encoding='utf-8').read()
text = re.sub(r'^PODCLOUD_JWT_SECRET=.*$', f'PODCLOUD_JWT_SECRET={secret}', text, flags=re.M)
text = re.sub(r'^WEB_PORT=.*$', f'WEB_PORT={port}', text, flags=re.M)
text = re.sub(r'^PUBLIC_BASE_URL=.*$', f'PUBLIC_BASE_URL={base}', text, flags=re.M)
text = re.sub(r'^PODCLOUD_IS_PRIVATE=.*$', f'PODCLOUD_IS_PRIVATE={private}', text, flags=re.M)
open('.env', 'w', encoding='utf-8').write(text)
PY
  ok ".env 已生成（含随机 JWT 密钥）"
fi
grep -qE '^PODCLOUD_JWT_SECRET=.+' .env || fail ".env 里 PODCLOUD_JWT_SECRET 为空——填一个随机值后重跑"

step "2/5 构建镜像（首次约 2-5 分钟）"
docker compose build
ok "镜像构建完成"

step "3/5 启动服务"
docker compose up -d
ok "容器已启动"

step "4/5 等待就绪"
URL="http://127.0.0.1:${WEB_PORT}"
for i in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "$URL/api/v1/auth/config" || true)"
  [ "$code" = "200" ] && { ok "健康检查通过（web + API）"; break; }
  [ "$i" = "60" ] && fail "等待超时。看日志：docker compose logs --tail 50 podcloud-server"
  sleep 2
done

step "5/5 管理员"
if [ -n "$ADMIN_EMAIL" ] && [ -n "${ADMIN_PASSWORD:-}" ]; then
  docker compose exec -T podcloud-server \
    python -m scripts.bootstrap_admin --email "$ADMIN_EMAIL" --password "$ADMIN_PASSWORD" \
    | tail -1 || warn "管理员创建失败（可能已存在），可在页面自助注册"
else
  warn "未提供 ADMIN_EMAIL/ADMIN_PASSWORD —— 跳过建管理员（公开模式下可在页面自助注册）"
fi

echo
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Pod Cloud 部署完成${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo "  访问地址 : $URL"
echo "  数据卷   : podcloud-data（SQLite 在 /app/data/podcloud.db）"
echo "  日志     : docker compose logs -f podcloud-server"
echo "  停止     : docker compose down        （加 -v 会连数据一起删）"
echo
echo "  下一步（在跑 agent 的机器上）："
echo "    1) 控制台「Agent 资产」注册 agent，复制一键接入命令执行"
echo "    2) 或   bash scripts/install.sh  装本地 CLI，再跑 scripts/setup-agent.sh"
echo
