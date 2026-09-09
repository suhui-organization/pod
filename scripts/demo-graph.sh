#!/usr/bin/env bash
# 5 分钟 demo：静态能力图 → 毒性路径 → 定点策略 diff
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
cd "$REPO_DIR"

if [ ! -d "$REPO_DIR/node_modules/tsx" ]; then
  echo "缺少 tsx，请先运行: pnpm install" >&2
  exit 1
fi

HOME_DIR="$TMP_DIR/home"
mkdir -p "$HOME_DIR"
cat > "$HOME_DIR/.claude.json" <<EOF
{
  "mcpServers": {
    "demo": {
      "command": "$(command -v node)",
      "args": ["--import", "tsx", "$REPO_DIR/apps/cli/test/fixtures/graph/danger-server.ts"]
    }
  }
}
EOF

cat > "$TMP_DIR/baseline.json" <<'EOF'
{
  "version": "0.1.0",
  "agent": "claude-code",
  "defaultDecision": "deny",
  "servers": {
    "demo": {
      "allow": ["read_file", "send_email", "execute_command", "http_request", "delete_file"]
    }
  }
}
EOF

POD=(node --import tsx "$REPO_DIR/apps/cli/src/index.ts")

echo "== 1/3 构建静态能力图 =="
"${POD[@]}" graph build --home "$HOME_DIR" --out "$TMP_DIR/potential.json"

echo
echo "== 2/3 识别毒性路径 =="
"${POD[@]}" graph toxic --graph "$TMP_DIR/potential.json" --out-dir "$TMP_DIR" \
  --diff "$TMP_DIR/baseline.json" --min-confidence 0.4 || true

echo
echo "== 3/3 定点策略 diff =="
cat "$TMP_DIR/policy-diff.json"
