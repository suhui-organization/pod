#!/usr/bin/env bash
# ============================================================================
# i18n-coverage.sh — 中英文完成度自查（约定：中文原文即词条键）
#
#   bash scripts/i18n-coverage.sh            # 列出还没英文词条的串 + 词表里的僵尸键
#   bash scripts/i18n-coverage.sh --strict   # 有缺口时退出码 1（可挂 CI / 发布前）
#
# 为什么需要它：`t()` 查不到词条会**静默回退中文**，所以"代码里包了 t()"
# 不等于"这句翻译过了"。把两边的键集合做差集，差集就是剩余进度。
# 两个方向的差都有意义：
#   - 代码有、词表没有 → 还没翻（界面上会显示中文）
#   - 词表有、代码没有 → 僵尸键：要么文案改了没删，要么键写错（多/少空格）
#     真实翻过车：词表少了前导空格，"修复: pod onboard…" 的英文一直不生效
#
# 覆盖范围：CLI（apps/cli + packages/*）与 Web 前端（cloud/web）。
# 服务端另有一套约定（路由照常写中文，出口统一翻译），其词表在
# cloud/server/app/i18n.py，键是格式化后的消息，无法用同一套差集比对。
#
# 它看不见什么：**完全没包 t() 的硬编码中文**（例如 `label: '总览'`）、
# 以及跨行写法的 t(\n '…' )。这两类只能靠界面走查，脚本只保证"包了 t() 的
# 都有词条"。
# ============================================================================
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"
STRICT=0
[ "${1:-}" = "--strict" ] && STRICT=1

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 调用点：`t('键'` / `tr('键'` → 裸键
used_keys_of() {
  grep -hoE "\b(t|tr)\('[^']*'" "${@:2}" \
    | sed "s/^[A-Za-z]*('//; s/'\$//" \
    | LC_ALL=C sort -u > "$1"
}

# 词表的两种写法都要认：带引号 `  '键': …`，以及不带引号的 `  键: …`
# （中文是合法 JS 标识符，词表里确实混着这两种；只认一种就会把已有词条误报成缺口）
cat_keys_of() {
  {
    grep -hoE "^  '[^']*':" "$1" | sed "s/^  '//; s/':$//"
    grep -hoE "^  [^' /][^:]*:" "$1" | sed "s/^  //; s/:$//"
  } | LC_ALL=C sort -u > "$2"
}

TOTAL_MISSING=0

# $1=面名称  $2=代码里用到的键  $3=词表已有的键
report() {
  local name="$1" used="$2" cat="$3"
  # 抽不到东西 = 抽取器坏了，不是"没有缺口"。宁可大声失败也别给假绿灯。
  if [ ! -s "$used" ] || [ ! -s "$cat" ]; then
    echo -e "${RED}❌ ${name}：键集合是空的（用了 $used / $cat），抽取器可能失效了${NC}"
    exit 2
  fi
  comm -23 "$used" "$cat" > "$TMP/missing.txt" # 还没翻
  comm -13 "$used" "$cat" > "$TMP/orphan.txt"  # 僵尸键
  local n_used n_missing n_orphan n_done pct
  n_used=$(wc -l < "$used" | tr -d ' ')
  n_missing=$(wc -l < "$TMP/missing.txt" | tr -d ' ')
  n_orphan=$(wc -l < "$TMP/orphan.txt" | tr -d ' ')
  n_done=$((n_used - n_missing))
  pct=0
  [ "$n_used" -gt 0 ] && pct=$((n_done * 100 / n_used))

  printf '%-4s 覆盖 %s/%s（%s%%）  未翻 %s  僵尸键 %s\n' "$name" "$n_done" "$n_used" "$pct" "$n_missing" "$n_orphan"
  TOTAL_MISSING=$((TOTAL_MISSING + n_missing))

  if [ "$n_missing" -gt 0 ]; then
    echo -e "  ${YELLOW}以下串在英文界面下仍显示中文：${NC}"
    sed 's/^/    /' "$TMP/missing.txt"
  fi
  if [ "$n_orphan" -gt 0 ]; then
    echo -e "  ${YELLOW}以下词条没有匹配的 t() 调用（改了文案没删 / 键不一致 / 还没接上）：${NC}"
    sed 's/^/    /' "$TMP/orphan.txt"
  fi
  echo
}

# ── CLI：apps/cli + packages/*，入口统一是 t()；跳过 i18n 自身（文档/测试里的示例串）
find apps/cli/src packages/*/src -name '*.ts' ! -name '*.test.ts' ! -path 'packages/i18n/src/*' > "$TMP/cli-files.txt"
used_keys_of "$TMP/cli-used.txt" $(cat "$TMP/cli-files.txt")
cat_keys_of packages/i18n/src/en-US.ts "$TMP/cli-cat.txt"
report "CLI" "$TMP/cli-used.txt" "$TMP/cli-cat.txt"

# ── Web：cloud/web/src（Vue 里 t() 与 tr() 两种叫法都存在），跳过 i18n 自身
find cloud/web/src \( -name '*.ts' -o -name '*.vue' \) ! -path '*/i18n/*' > "$TMP/web-files.txt"
used_keys_of "$TMP/web-used.txt" $(cat "$TMP/web-files.txt")
cat_keys_of cloud/web/src/i18n/en-US.ts "$TMP/web-cat.txt"
report "Web" "$TMP/web-used.txt" "$TMP/web-cat.txt"

# ── 额外守卫：Vue 模板会在编译期解码 HTML 实体 ──────────────────────────────
# 模板里写 tr('a &gt; b')，运行时传给 t() 的键是 'a > b'，而词表里存的是 'a &gt; b'
# ——永远匹配不上，界面静默回退中文。上面的差集看不出来（两边源码文本是一致的）。
# 真机踩过：策略页副标题、调用链页说明、接入命令里的 <名字>，英文界面下全是中文。
ENTITY_KEYS=$(grep -nE "^  '[^']*(&lt;|&gt;)" cloud/web/src/i18n/en-US.ts || true)
if [ -n "$ENTITY_KEYS" ]; then
  echo -e "${RED}❌ Web 词表里有 HTML 实体键${NC}：Vue 模板编译时会解码，运行时永远匹配不上"
  echo "$ENTITY_KEYS" | sed 's/^/    /'
  echo "    改用原始字符（> / <），模板与词表两边都改。"
  echo
  TOTAL_MISSING=$((TOTAL_MISSING + 1))
fi

if [ "$TOTAL_MISSING" -eq 0 ]; then
  echo -e "${GREEN}✅ 所有 t() 键都有英文词条${NC}"
elif [ "$STRICT" = "1" ]; then
  echo -e "${RED}❌ 共 $TOTAL_MISSING 条未翻译（--strict）${NC}"
  exit 1
fi
