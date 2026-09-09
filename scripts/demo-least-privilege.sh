#!/usr/bin/env bash
# ============================================================================
# demo-least-privilege.sh — 5 分钟演示路线 A：
#   真实行为语料 → 最小权限策略草稿 → 与"全放开"基线的 diff
#
# 不依赖任何 agent、不上传任何数据、不修改你的 ~/.pod：
# 所有审计与草稿都写在临时目录里，退出即删除。
#
# 用法（在仓库根目录）：
#   pnpm install          # 首次需要，提供 tsx
#   bash scripts/demo-least-privilege.sh
# ============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

AUDIT_DIR="$TMP_DIR/audit"
DRAFT_FILE="$TMP_DIR/draft.json"
BASELINE="$REPO_DIR/examples/baseline-demo.json"

if [ ! -d "$REPO_DIR/node_modules/tsx" ]; then
  echo "缺少 tsx，请先在 $REPO_DIR 运行: pnpm install" >&2
  exit 1
fi

# 跨包导入走 dist/；干净克隆后先构建一次，否则 demo 找不到 @podsec/* 产物。
if [ ! -f "$REPO_DIR/packages/audit/dist/index.js" ]; then
  echo "首次运行：构建 workspace 包（pnpm build）..."
  (cd "$REPO_DIR" && pnpm build >/dev/null) || {
    echo "构建失败，请手动运行: cd $REPO_DIR && pnpm install && pnpm build" >&2
    exit 1
  }
fi

POD=(node --import tsx "$REPO_DIR/apps/cli/src/index.ts")

seed() {
  local server="$1" tool="$2" decision="$3" outcome="$4" reason="${5:-}"
  local args=(ingest --agent demo-agent --server "$server" --tool "$tool"
              --decision "$decision" --outcome "$outcome" --audit-dir "$AUDIT_DIR")
  if [ -n "$reason" ]; then args+=(--reason "$reason"); fi
  "${POD[@]}" "${args[@]}" >/dev/null 2>&1
}

repeat_seed() {
  local n="$1"; shift
  for _ in $(seq 1 "$n"); do seed "$@"; done
}

echo
echo "== 1/4 采集真实行为语料（模拟一个 agent 正常工作一周） =="
repeat_seed 10 filesystem read_file      allow ok
repeat_seed  5 filesystem list_directory allow ok
repeat_seed  3 filesystem search_files   allow ok
repeat_seed  4 filesystem write_file     allow ok
repeat_seed  2 filesystem edit_file      allow ok
repeat_seed  2 github     create_issue   allow ok
repeat_seed  2 github     create_pull_request allow ok
repeat_seed  1 shell      execute_command     allow ok
repeat_seed  1 email      send_email          allow ok

# 两个"出事"的调用：删除 + 碰到 .env
seed filesystem delete_file deny blocked
seed filesystem read_file  deny blocked 'argument hits sensitive path pattern ".env" (secrets-input)'
echo "  ✅ 已写入 $(find "$AUDIT_DIR" -name '*.jsonl' | wc -l | tr -d ' ') 条哈希链审计文件"

echo
echo "== 2/4 当前基线：几乎全放开（大多数人的真实起点） =="
node -e "
const p = require('$BASELINE');
console.log('  defaultDecision:', p.defaultDecision);
for (const [s, r] of Object.entries(p.servers)) console.log('  ' + s + ': allow ' + r.allow.join(', '));
"

echo
echo "== 3/4 pod 从真实行为编译最小权限策略 =="
"${POD[@]}" policy draft --audit-dir "$AUDIT_DIR" --agent demo-agent \
  --out "$DRAFT_FILE" --diff "$BASELINE"

echo
echo "== 4/4 生成的策略文件 =="
cat "$DRAFT_FILE"
echo
echo "下一步（真实环境）：pod lint --policy <draft> → 人工复核 → pod serve --policy <draft>"
