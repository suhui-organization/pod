#!/usr/bin/env bash
# ============================================================================
# setup-agent.sh — 把本机 agent（默认 Hermes）接入 Pod Cloud 的完整路径（幂等）
#
# 一条命令完成: 服务可达检查 → pod CLI 就绪(缺失则从源码构建) → cloud.json 绑定
#   (可全自动注册 agent) → 策略就绪 → 网关进程 → Hermes MCP 配置 →
#   首次同步(401 自动轮换 token) → 云端状态验证
#
# 用法:
#   bash setup-agent.sh                                        # 绑定已存在时
#   ADMIN_EMAIL=admin@x.com ADMIN_PASSWORD=xxx bash setup-agent.sh   # 全自动(含注册/轮换)
#
# 环境变量(全部可选):
#   POD_API          服务端地址（默认 http://127.0.0.1:18088）
#   AGENT_NAME       本地 agent 身份（默认 hermes，须与 cloud.json 的 local_agent 一致）
#   MCP_KEY          Hermes 配置里的 server 名（默认 pod-filesystem）
#   SERVER_KEY       网关 server 标识/审计文件名（默认 filesystem）
#   GATEWAY_PORT     网关 HTTP 端口（默认 8787）
#   ROOT_DIR         filesystem 上游暴露的根目录（默认 $HOME/Workspaces）
#   UPSTREAM_CMD / UPSTREAM_PACKAGE   上游启动命令与 npm 包（默认 npx + @modelcontextprotocol/server-filesystem）
#   POLICY_FILE      策略文件（默认 ~/.pod/policies/baseline.json）
#   POD_REPO         pod 仓库根（默认本脚本所在 ../；CLI 缺失时用于构建）
#   CLOUD_JSON       cloud.json 路径（默认 ~/.pod/cloud.json）
#   HERMES_CONFIG    Hermes config.yaml 路径（默认自动探测 HERMES_HOME 等）
#   ADMIN_EMAIL/ADMIN_PASSWORD   管理员凭据：缺绑定时自动注册 agent；同步 401 时自动轮换
#   REBUILD_CLI=1    强制重新构建 pod CLI
#
# 说明: 网关与端口转发都是常驻进程（pid 文件在 ~/.pod/），重复运行会复用/平滑重启。
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POD_REPO="${POD_REPO:-$(cd "$SCRIPT_DIR/.." && pwd)}"
POD_HOME="${HOME}/.pod"
CLOUD_JSON="${CLOUD_JSON:-$POD_HOME/cloud.json}"
POLICY_FILE="${POLICY_FILE:-$POD_HOME/policies/baseline.json}"
POD_API="${POD_API:-http://127.0.0.1:18088}"
AGENT_NAME="${AGENT_NAME:-hermes}"
MCP_KEY="${MCP_KEY:-pod-filesystem}"
SERVER_KEY="${SERVER_KEY:-filesystem}"
GATEWAY_PORT="${GATEWAY_PORT:-8787}"
ROOT_DIR="${ROOT_DIR:-$HOME/Workspaces}"
UPSTREAM_CMD="${UPSTREAM_CMD:-npx}"
UPSTREAM_PACKAGE="${UPSTREAM_PACKAGE:-@modelcontextprotocol/server-filesystem}"
# 同机多 agent 时每个 agent 独立网关进程/审计目录/配置文件。
# 审计目录规范: audit/<名称净化>/ ——名称(如含空格)统一转 '-',保证同一 agent 永远
# 落到同一条链(否则 sync 扫描到同 server 多文件会重复推,触发 409)。
SAFE_NAME="$(printf '%s' "$AGENT_NAME" | tr -c 'A-Za-z0-9' '-')"
if [ -n "${AUDIT_DIR:-}" ]; then
  : # 显式指定优先(迁移/兼容场景)
elif [ "$AGENT_NAME" = "hermes" ]; then
  AUDIT_DIR="" # hermes 为单 agent 旧布局(顶层 ~/.pod/audit),保持兼容
else
  AUDIT_DIR="$POD_HOME/audit/$SAFE_NAME"
fi
GW_PID_FILE="$POD_HOME/gateway-${AGENT_NAME}-${SERVER_KEY}.pid"
GW_LOG="$POD_HOME/gateway-${AGENT_NAME}-${SERVER_KEY}.log"
CONFIG_TARGET="${CONFIG_TARGET:-${HERMES_CONFIG:-}}"       # 目标 agent 配置文件(.yaml 合并 / .toml 走 codex mcp)
CODEX_BIN="${CODEX_BIN:-/usr/lib/chatgpt/resources/codex}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'
ok()  { echo -e "${GREEN}[ok]${NC}   $*"; }
warn(){ echo -e "${YELLOW}[warn]${NC} $*"; }
fail(){ echo -e "${RED}[fail]${NC} $*" >&2; exit 1; }
step(){ echo; echo -e "${GREEN}── $*${NC}"; }

# JSON 工具函数（避免 sed 解析）
jget(){ python3 -c "import json,sys; d=json.load(sys.stdin); print(d$1)" 2>/dev/null || true; }
admin_token() { # → echo access_token（依赖 ADMIN_EMAIL/ADMIN_PASSWORD）
  curl -fsS --max-time 10 -X POST "$POD_API/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\",\"client\":\"web\"}" | jget "['access_token']"
}

# ── all 模式: 处理 cloud.json 里这台机器的全部 agent（每 agent 一个网关）──
MODE="${1:-}"
if [ "$MODE" = "all" ] && [ "${SETUP_ALL_CHILD:-0}" != "1" ]; then
  [ -f "$CLOUD_JSON" ] || fail "缺少 $CLOUD_JSON（先在目标机器执行 agent-setup 一键脚本注册）"
  NAMES="$(python3 - "$CLOUD_JSON" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
print("\n".join(b["local_agent"] for b in d.get("agents", [])))
EOF
)"
  [ -n "$NAMES" ] || fail "cloud.json 无任何绑定"
  echo -e "${GREEN}── all 模式: 处理 $(printf '%s\n' "$NAMES" | wc -l) 个本地绑定 ──${NC}"
  PORT_BASE=8786
  N=0
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    N=$((N+1))
    case "$name" in
      hermes*) PORT=8787; KEY="pod-filesystem"; AUD=""; CT="" ;;
      codex*|*codex) PORT=8788; KEY="pod-codex"; AUD="$POD_HOME/audit/codex"; CT="$HOME/.codex/config.toml" ;;
      *)
        # 其余平台: 网关照常起; MCP 写入按平台适配(见下)——未知平台给出手工指引
        PORT=$((PORT_BASE + N)); KEY="pod-$name"
        AUD="$POD_HOME/audit/$(printf '%s' "$name" | tr -c 'A-Za-z0-9' '-')"
        case "$name" in
          claude*|claude-code*) CT="$HOME/.claude.json" ;;
          cursor*)             CT="$HOME/.cursor/mcp.json" ;;
          openclaw*)           CT="$HOME/.config/openclaw/config.json" ;;
          dsh*)                CT="" ;;
          *)                   CT="" ;;
        esac
        ;;
    esac
    PF="$POD_HOME/policies/baseline-$name.json"
    [ "$name" = "hermes" ] && PF="$POLICY_FILE"
    echo; echo -e "${GREEN}===== [$N] agent: $name (port $PORT, key $KEY) =====${NC}"
    AGENT_NAME="$name" GATEWAY_PORT="$PORT" MCP_KEY="$KEY" AUDIT_DIR="$AUD" \
    CONFIG_TARGET="$CT" POLICY_FILE="$PF" SETUP_ALL_CHILD=1 \
    ADMIN_EMAIL="${ADMIN_EMAIL:-}" ADMIN_PASSWORD="${ADMIN_PASSWORD:-}" \
      bash "$0" || { warn "agent '$name' 接入失败，继续处理下一个"; }
  done <<< "$NAMES"
  echo
  echo -e "${GREEN}════════ all 完成: $N 个 agent ════════════${NC}"
  echo "  定时保活(建议每台机器 cron 每 5 分钟):  */5 * * * *  pod sync"
  echo "  未自动接 MCP 的平台: 按其配置格式手工把 agent 指向 http://127.0.0.1:<port>/mcp"
  echo "  (适配器按『平台』写一次即可覆盖该平台全部 agent，非按 agent)"
  exit 0
fi

# ── 0. 服务可达 ─────────────────────────────────────────────────────────────
step "0/7 服务端可达性: $POD_API"
curl -fsS --max-time 8 "$POD_API/api/v1/auth/config" >/dev/null \
  || fail "Pod Cloud 服务端不可达（先部署: podcloud-server/deploy/k8s/install-local.sh）"
ok "服务端在线"

# ── 1. pod CLI 就绪 ─────────────────────────────────────────────────────────
step "1/7 pod CLI"
if ! command -v pod >/dev/null 2>&1 || [ "${REBUILD_CLI:-0}" = "1" ]; then
  command -v node >/dev/null 2>&1 || fail "需要 Node.js >=20（构建 pod CLI）"
  command -v pnpm >/dev/null 2>&1 || warn "未找到 pnpm，尝试 npm 全局安装 @podsec/cli"
  if command -v pnpm >/dev/null 2>&1; then
    echo "  从 $POD_REPO 源码构建 ..."
    ( cd "$POD_REPO" && pnpm install >/dev/null 2>&1 && pnpm -r build >/dev/null ) \
      || fail "pod 构建失败（先确认仓库可 pnpm install）"
    mkdir -p "$HOME/.local/bin"
    ln -sf "$POD_REPO/apps/cli/dist/index.js" "$HOME/.local/bin/pod"
  else
    npm i -g @podsec/cli || fail "npm 安装 @podsec/cli 失败"
  fi
  hash -r
fi
command -v pod >/dev/null 2>&1 || fail "pod 仍未就绪（检查 ~/.local/bin 是否在 PATH）"
ok "pod CLI: $(command -v pod)"

# ── 2. cloud.json 绑定（缺绑定: 有管理员凭据则自动注册，否则给出手工指引）──
step "2/7 cloud.json 绑定 (agent=$AGENT_NAME)"
if [ -f "$CLOUD_JSON" ] && python3 - "$CLOUD_JSON" "$AGENT_NAME" <<'EOF' | grep -q yes
import json,sys
d=json.load(open(sys.argv[1]))
binds=d.get("agents") or []
print("yes" if any(b.get("local_agent")==sys.argv[2] for b in binds) else "no")
EOF
then
  ok "cloud.json 已含 $AGENT_NAME 绑定"
else
  if [ -n "${ADMIN_EMAIL:-}" ] && [ -n "${ADMIN_PASSWORD:-}" ]; then
    TOK="$(admin_token)"; [ -n "$TOK" ] || fail "管理员登录失败（检查 ADMIN_EMAIL/ADMIN_PASSWORD）"
    # 已存在同名 agent 时只补绑定（不重复注册）
    EXISTING_ID="$(curl -fsS --max-time 10 "$POD_API/api/v1/agents" -H "Authorization: Bearer $TOK" \
      | python3 -c "import json,sys; d=json.load(sys.stdin); print(next((a['id'] for a in d['agents'] if a['name']=='$AGENT_NAME'),''))")"
    if [ -n "$EXISTING_ID" ]; then
      AGENT_ID="$EXISTING_ID"
      NEW_TOKEN="$(curl -fsS --max-time 10 -X POST "$POD_API/api/v1/agents/$AGENT_ID/rotate-token" -H "Authorization: Bearer $TOK" | jget "['sync_token']")"
      ok "agent '$AGENT_NAME' 已存在(id=$AGENT_ID)，轮换 token 并绑定"
    else
      REG="$(curl -fsS --max-time 10 -X POST "$POD_API/api/v1/agents" -H "Authorization: Bearer $TOK" \
        -H 'Content-Type: application/json' -d "{\"name\":\"$AGENT_NAME\"}")"
      AGENT_ID="$(printf '%s' "$REG" | jget "['agent']['id']")"
      NEW_TOKEN="$(printf '%s' "$REG" | jget "['sync_token']")"
      ok "agent '$AGENT_NAME' 注册成功 (id=$AGENT_ID)"
    fi
    [ -n "$AGENT_ID" ] && [ -n "$NEW_TOKEN" ] || fail "注册/轮换响应缺字段"
    mkdir -p "$POD_HOME"
    python3 - "$CLOUD_JSON" "$AGENT_NAME" "$AGENT_ID" "$NEW_TOKEN" "$POD_API" <<'EOF'
import json, os, sys
p, name, aid, tok, api = sys.argv[1:]
d = json.load(open(p)) if os.path.exists(p) else {}
d.setdefault("api_url", api.rstrip("/"))
binds = d.setdefault("agents", [])
binds = [b for b in binds if b.get("local_agent") != name]
binds.append({"local_agent": name, "agent_id": int(aid), "sync_token": tok})
d["agents"] = binds
json.dump(d, open(p, "w"), indent=2)
print("cloud.json 已写入绑定", name, "->", aid)
EOF
  else
    fail "cloud.json 缺 $AGENT_NAME 绑定。两种方式任选：
      A) 在 Web 控制台($POD_API) 注册 agent '$AGENT_NAME'，把一键接入命令(| bash)执行一次后再重跑本脚本；
      B) 带上 ADMIN_EMAIL/ADMIN_PASSWORD 重跑，自动完成注册+绑定。"
  fi
fi

# ── 3. 策略就绪（baseline，缺省自动创建并贴合当前 agent/server）───────────
step "3/7 策略: $POLICY_FILE"
if [ ! -f "$POLICY_FILE" ]; then
  mkdir -p "$(dirname "$POLICY_FILE")"
  if [ -f "$POD_HOME/policies/baseline.json" ]; then
    cp "$POD_HOME/policies/baseline.json" "$POLICY_FILE"   # 复用已有 baseline 再对齐
  else
    pod init --template baseline >/dev/null 2>&1 || fail "pod init 失败"
    cp "$POD_HOME/policies/baseline.json" "$POLICY_FILE"
  fi
  ok "策略已创建: $POLICY_FILE"
fi
python3 - "$POLICY_FILE" "$AGENT_NAME" "$SERVER_KEY" "$UPSTREAM_CMD" "$UPSTREAM_PACKAGE" <<'EOF'
import json, sys
p, agent, server, cmd, pkg = sys.argv[1:]
d = json.load(open(p))
d.setdefault("version", "0.1.0")
d["agent"] = agent
sv = d.setdefault("servers", {}).setdefault(server, {})
# 幂等归一化: 缺省只读操作补齐(新加 get_file_info: 只读元数据应放行,非 fail-closed 目标)
DEFAULT_ALLOW = ["read_file", "list_directory", "search_files", "get_file_info"]
allow = [x for x in sv.get("allow", []) if isinstance(x, str)]
for op in DEFAULT_ALLOW:
    if op not in allow:
        allow.append(op)
sv["allow"] = allow
sv.setdefault("approve", ["write_file", "edit_file"])
sv.setdefault("deny", ["delete_file"])
sv["source"] = {"command": cmd, "package": pkg}
json.dump(d, open(p, "w"), ensure_ascii=False, indent=2)
print("策略已对齐: agent=%s server=%s source=%s/%s allow=%s" % (agent, server, cmd, pkg, ",".join(sv["allow"])))
EOF

# ── 4. 网关进程（已在跑且健康则复用）───────────────────────────────────────
step "4/7 网关: http://127.0.0.1:$GATEWAY_PORT/mcp (agent=$AGENT_NAME server=$SERVER_KEY)"
gw_alive() {
  [ -f "$GW_PID_FILE" ] || return 1
  kill -0 "$(cat "$GW_PID_FILE")" 2>/dev/null || return 1
  curl -fsS --max-time 5 -o /dev/null -X POST "http://127.0.0.1:$GATEWAY_PORT/mcp" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' 2>/dev/null
}
gw_probe() { # 端口已有健康网关(可能无 pid 文件)——返回其 pid 或空
  curl -fsS --max-time 5 -o /dev/null -X POST "http://127.0.0.1:$GATEWAY_PORT/mcp" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' 2>/dev/null \
    && pgrep -f "pod serve --agent $AGENT_NAME --server $SERVER_KEY" 2>/dev/null | head -1 || true
}
if gw_alive; then
  ok "网关已在运行 (pid $(cat "$GW_PID_FILE"))，跳过启动"
elif [ -n "$(gw_probe)" ]; then
  # 端口上已有健康网关但没有(或失效的)pid 文件(手工启动/旧版本脚本)——接管
  echo "$(gw_probe)" > "$GW_PID_FILE"
  ok "接管已在运行的网关 (pid $(cat "$GW_PID_FILE"))"
else
  [ -f "$GW_PID_FILE" ] && kill "$(cat "$GW_PID_FILE")" 2>/dev/null || true
  AUDIT_ARGS=()
  [ -n "$AUDIT_DIR" ] && AUDIT_ARGS=(--audit-dir "$AUDIT_DIR")
  nohup pod serve --agent "$AGENT_NAME" --server "$SERVER_KEY" --policy "$POLICY_FILE" \
    "${AUDIT_ARGS[@]}" \
    --command "$UPSTREAM_CMD" --arg -y --arg "$UPSTREAM_PACKAGE" --arg "$ROOT_DIR" \
    --transport http --port "$GATEWAY_PORT" >"$GW_LOG" 2>&1 &
  echo "$!" > "$GW_PID_FILE"
  echo "  启动中(首次会 npx 拉取上游包，可能较慢)..."
  for i in $(seq 1 40); do gw_alive && break; sleep 1; done
  gw_alive || { echo "  网关日志尾部:"; tail -5 "$GW_LOG" 2>/dev/null; fail "网关未就绪"; }
  ok "网关已启动 (pid $(cat "$GW_PID_FILE"), 日志 $GW_LOG)"
fi

# ── 5. agent 的 MCP 配置（yaml → 直接合并; toml → codex mcp add; 均幂等）──
step "5/7 agent MCP 配置 (key=$MCP_KEY)"
if [ -z "$CONFIG_TARGET" ]; then
  # 未显式指定:仅 hermes 走已知 yaml 布局探测;其余平台须显式传 CONFIG_TARGET
  # (多平台适配器按“平台”写一次，覆盖该平台全部 agent)
  case "$AGENT_NAME" in
    hermes*)
      for cand in "${HERMES_HOME:-}/config.yaml" "$HOME/Applications/hermes/config.yaml" "$HOME/.config/hermes/config.yaml"; do
        if [ -n "$cand" ] && [ -f "$cand" ]; then CONFIG_TARGET="$cand"; break; fi
      done
      ;;
  esac
fi
case "${CONFIG_TARGET##*.}" in
  yml|yaml)
    if [ -f "$CONFIG_TARGET" ]; then
      python3 - "$CONFIG_TARGET" "$MCP_KEY" "$GATEWAY_PORT" <<'EOF'
import sys, time
p, key, port = sys.argv[1:]
try:
    import yaml
except ImportError:
    print("SKIP: 无 pyyaml，跳过自动写入（手工: hermes mcp add %s --url http://127.0.0.1:%s/mcp）" % (key, port))
    sys.exit(0)
import shutil
shutil.copy2(p, p + ".podcloud.bak-%d" % int(time.time()))
d = yaml.safe_load(open(p)) or {}
servers = d.setdefault("mcp_servers", {})
if key in servers:
    print("MCP 配置已存在:", key, "->", servers[key].get("url"))
else:
    servers[key] = {"url": "http://127.0.0.1:%s/mcp" % port, "enabled": True}
    yaml.safe_dump(d, open(p, "w"), allow_unicode=True, sort_keys=False)
    print("已写入 MCP 配置:", key)
EOF
      ok "yaml 配置就绪: $CONFIG_TARGET"
    else
      warn "目标配置文件不存在: $CONFIG_TARGET（用 CONFIG_TARGET 指定）"
    fi
    ;;
  toml)
    if [ -x "$CODEX_BIN" ]; then
      if "$CODEX_BIN" mcp list 2>/dev/null | grep -q "$MCP_KEY"; then
        ok "codex 已配置 $MCP_KEY（$CODEX_BIN mcp list 确认）"
      else
        "$CODEX_BIN" mcp add "$MCP_KEY" --url "http://127.0.0.1:$GATEWAY_PORT/mcp" \
          && ok "codex mcp add $MCP_KEY --url http://127.0.0.1:$GATEWAY_PORT/mcp"
      fi
    else
      warn "未找到 codex CLI($CODEX_BIN)，手工执行: codex mcp add $MCP_KEY --url http://127.0.0.1:$GATEWAY_PORT/mcp"
    fi
    ;;
  *)
    warn "未识别 CONFIG_TARGET($CONFIG_TARGET) 类型，跳过自动配置；手工: hermes/codex mcp add $MCP_KEY --url http://127.0.0.1:$GATEWAY_PORT/mcp"
    ;;
esac

# ── 6. 首次同步（401 = token 失配: 有管理员凭据自动轮换，否则给指引）──────
step "6/7 同步审计"
sync_once() { pod sync 2>&1 || true; }
OUT="$(sync_once)"
if printf '%s' "$OUT" | grep -q "401"; then
  warn "同步 401：sync token 与服务端不一致"
  if [ -n "${ADMIN_EMAIL:-}" ] && [ -n "${ADMIN_PASSWORD:-}" ]; then
    TOK="$(admin_token)"
    AGENT_ID="$(python3 - "$CLOUD_JSON" "$AGENT_NAME" <<'EOF'
import json,sys
d=json.load(open(sys.argv[1]))
print(next((b["agent_id"] for b in d.get("agents",[]) if b.get("local_agent")==sys.argv[2]),""))
EOF
)"
    [ -n "$AGENT_ID" ] || fail "cloud.json 中找不到 $AGENT_NAME 的 agent_id"
    NEW_TOKEN="$(curl -fsS --max-time 10 -X POST "$POD_API/api/v1/agents/$AGENT_ID/rotate-token" -H "Authorization: Bearer $TOK" | jget "['sync_token']")"
    [ -n "$NEW_TOKEN" ] || fail "轮换 token 失败"
    python3 - "$CLOUD_JSON" "$AGENT_NAME" "$NEW_TOKEN" <<'EOF'
import json, sys
p, name, tok = sys.argv[1:]
d = json.load(open(p))
for b in d.setdefault("agents", []):
    if b.get("local_agent") == name:
        b["sync_token"] = tok
json.dump(d, open(p, "w"), indent=2)
print("cloud.json token 已更新")
EOF
    OUT="$(sync_once)"
  fi
fi
printf '%s\n' "$OUT" | grep -v "^\[pod\] " | grep -v '^$' || true
printf '%s\n' "$OUT" | grep -qE "total synced|nothing to sync" || fail "同步异常（见上）"
ok "同步执行完成"

# ── 7. 云端状态验证（有管理员凭据时）──────────────────────────────────────
step "7/7 云端验证"
if [ -n "${ADMIN_EMAIL:-}" ] && [ -n "${ADMIN_PASSWORD:-}" ]; then
  TOK="$(admin_token)"
  curl -fsS --max-time 10 "$POD_API/api/v1/agents" -H "Authorization: Bearer $TOK" \
    | python3 -c "
import json,sys
d=json.load(sys.stdin)
a=next((x for x in d['agents'] if x['name']=='$AGENT_NAME'),None)
print('  agent:', a['name'], '| status:', a['status'], '| events:', a['event_count'], '| last_seen:', a['last_seen_at']) if a else print('  未找到 agent $AGENT_NAME')"
else
  warn "未提供管理员凭据，跳过云端状态回读（网页时间线同样可见）"
fi

echo
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  agent '$AGENT_NAME' 接入完成${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo "  网关   : http://127.0.0.1:$GATEWAY_PORT/mcp (pid $(cat "$GW_PID_FILE"))"
echo "  策略   : $POLICY_FILE"
echo "  审计   : $POD_HOME/audit/"
echo "  常用   : pod audit / pod pending / pod approve --id N / pod sync"
echo "  重启后 : bash $SCRIPT_DIR/setup-agent.sh   # 幂等，自动拉起网关与转发"
