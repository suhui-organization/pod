#!/usr/bin/env bash
# ============================================================================
# onboard-agents.sh — 批量注册 agent 并产出逐台机器的一键接入命令（规模化接入）
#
# 输入: 每行一个 agent，TSV/CSV，字段: name [platform [machine]]
#   - platform 可省略（服务端按名字自动推断 hermes/codex/claude-code/cursor/…）
#   - machine  可省略；提供时按机器分组输出，方便一次性分发给各台机器
# 输出: 每行一条 setup URL（凭据即 URL 内 sync token，与 Web 一键接入同款）:
#       curl -fsSL <api>/api/v1/agent-setup/<id>/<token> | bash
#   同时落盘 <OUT_FILE>（默认 ./onboard-agents.tsv）
#
# 用法:
#   ADMIN_EMAIL=admin@x.com ADMIN_PASSWORD=xxx \
#     POD_API=http://127.0.0.1:18088 bash scripts/onboard-agents.sh agents.tsv
#   …同上 --rotate    # 已存在的 agent 也强制轮换 token 并输出新 URL（旧 URL 立即失效）
#
# 幂等: 不传 --rotate 时已存在同名 agent 跳过（不重复注册、不轮换）。
# ============================================================================
set -euo pipefail

POD_API="${POD_API:-http://127.0.0.1:18088}"
IN_FILE="${1:-}"
ROTATE=0
[ "${2:-}" = "--rotate" ] && ROTATE=1
OUT_FILE="${OUT_FILE:-./onboard-agents.tsv}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'
ok()  { echo -e "${GREEN}[ok]${NC}   $*"; }
warn(){ echo -e "${YELLOW}[warn]${NC} $*"; }
fail(){ echo -e "${RED}[fail]${NC} $*" >&2; exit 1; }

[ -n "${ADMIN_EMAIL:-}" ] && [ -n "${ADMIN_PASSWORD:-}" ] || fail "需要 ADMIN_EMAIL/ADMIN_PASSWORD"
[ -n "$IN_FILE" ] && [ -f "$IN_FILE" ] || fail "用法: $0 <agents.tsv|.csv> [--rotate]  (字段: name [platform [machine]])"
command -v curl >/dev/null || fail "缺少 curl"

# ── 登录 ───────────────────────────────────────────────────────────────────
TOK="$(curl -fsS --max-time 10 -X POST "$POD_API/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\",\"client\":\"web\"}" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
[ -n "$TOK" ] || fail "管理员登录失败"
AUTH=(-H "Authorization: Bearer $TOK")

# 现有 agents（幂等判断用）
MAP_JSON="$(curl -fsS --max-time 10 "$POD_API/api/v1/agents" "${AUTH[@]}")"

total=0; created=0; rotated=0; skipped=0
: > "$OUT_FILE"

while IFS=$'\t, ' read -r name platform machine rest; do
  [ -n "$name" ] || continue
  [[ "$name" == \#* ]] && continue
  machine="${machine:-}"
  platform="${platform:-}"

  EXISTING_ID="$(printf '%s' "$MAP_JSON" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(next((a['id'] for a in d['agents'] if a['name']=='$name'),''))")"

  if [ -n "$EXISTING_ID" ] && [ "$ROTATE" != "1" ]; then
    warn "跳过(已存在 id=$EXISTING_ID): $name（--rotate 强制轮换出新 URL）"
    skipped=$((skipped+1)); continue
  fi

  if [ -n "$EXISTING_ID" ]; then
    # 轮换: 旧 URL 立即失效
    BODY="$(curl -fsS --max-time 10 -X POST "$POD_API/api/v1/agents/$EXISTING_ID/rotate-token" "${AUTH[@]}")"
    AGENT_ID="$EXISTING_ID"
    TOKEN="$(printf '%s' "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sync_token"])')"
    rotated=$((rotated+1))
    ok "轮换: $name (id=$AGENT_ID)"
  else
    PLATFORM_ARG=()
    [ -n "$platform" ] && PLATFORM_ARG=(-d "{\"name\":\"$name\",\"platform\":\"$platform\"}") \
                     || PLATFORM_ARG=(-d "{\"name\":\"$name\"}")
    BODY="$(curl -fsS --max-time 10 -X POST "$POD_API/api/v1/agents" "${AUTH[@]}" \
      -H 'Content-Type: application/json' "${PLATFORM_ARG[@]}")"
    AGENT_ID="$(printf '%s' "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["agent"]["id"])')"
    TOKEN="$(printf '%s' "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sync_token"])')"
    created=$((created+1))
    ok "注册: $name (id=$AGENT_ID${platform:+, platform=$platform})"
  fi

  URL="$POD_API/api/v1/agent-setup/$AGENT_ID/$TOKEN"
  printf '%s\t%s\t%s\t%s\t%s\n' "$machine" "$name" "${platform:-auto}" "$AGENT_ID" "$URL" >> "$OUT_FILE"
  total=$((total+1))
done < "$IN_FILE"

echo
echo -e "${GREEN}════════ 批量接入结果 ════════════${NC}"
echo "  输入清单: $IN_FILE"
echo "  新注册  : $created    轮换: $rotated    跳过(已存在): $skipped"
echo "  产出 URL: $total 条 → $OUT_FILE"
echo
echo "  分发方式(每台机器执行其行即可，脚本幂等，会自合并 cloud.json 并验证同步):"
awk -F'\t' '$1!=""{print "  ["$1"] "$4"  →  curl -fsSL \""$5"\" | bash"}' "$OUT_FILE"
echo
echo "  机器列留空的行: curl -fsSL \"$POD_API/api/v1/agent-setup/<id>/<token>\" | bash"
echo "  接入后该机器上再跑: bash <pod 仓库>/scripts/setup-agent.sh all  (自动为本地每个 agent 起网关并接好 MCP)"
