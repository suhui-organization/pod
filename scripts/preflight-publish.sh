#!/usr/bin/env bash
# ============================================================================
# preflight-publish.sh — 发布前必跑检查（可重复、可挂 CI）
#
#   bash scripts/preflight-publish.sh          # 全量（含干净环境安装，约 2-3 分钟）
#   bash scripts/preflight-publish.sh --quick  # 跳过安装，只查静态一致性（秒级）
#
# 这些检查对应"读者照着做会不会失败"，不是代码风格检查。每一条都能追溯到
# 一次真实翻车：npm 包不存在、OWASP 编号是编的、链接打不开、安装链接没钉版本、
# serve 例子被策略拦下。
# ============================================================================
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"
QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo -e "  ${GREEN}✅${NC} $*"; }
bad()  { FAIL=$((FAIL+1)); echo -e "  ${RED}❌${NC} $*"; }
warn() { echo -e "  ${YELLOW}⚠️${NC}  $*"; }
step() { echo; echo "── $*"; }

# ── 1. 版本一致性 ───────────────────────────────────────────────────────────
step "1. 版本号一致（CHANGELOG / README / install.sh / apps/cli）"
CHANGELOG_VER="$(grep -m1 -oE '^## v[0-9]+\.[0-9]+\.[0-9]+' CHANGELOG.md 2>/dev/null | sed 's/## //')"
INSTALL_VER="$(grep -m1 -oE 'POD_VERSION:-v?[0-9]+\.[0-9]+\.[0-9]+' scripts/install.sh | sed 's/POD_VERSION:-//')"
README_VER="$(grep -m1 -oE 'raw/v[0-9]+\.[0-9]+\.[0-9]+/' README.md | sed 's#raw/##; s#/##')"
# `pod --version` 读的就是这个文件——版本号不一致时，用户自查会看到另一个数
CLI_VER="v$(python3 -c "import json;print(json.load(open('apps/cli/package.json'))['version'])" 2>/dev/null)"
[ -n "$CHANGELOG_VER" ] && ok "CHANGELOG 最新版本: $CHANGELOG_VER" || bad "CHANGELOG.md 找不到版本条目"
if [ "$INSTALL_VER" = "$CHANGELOG_VER" ]; then ok "install.sh 默认版本一致: $INSTALL_VER"
else bad "install.sh 默认 POD_VERSION=${INSTALL_VER}，但 CHANGELOG 是 ${CHANGELOG_VER}（发新版本时两处要一起改）"; fi
if [ "$README_VER" = "$CHANGELOG_VER" ]; then ok "README 安装链接钉在: $README_VER"
else bad "README 安装链接指向 ${README_VER}，与 ${CHANGELOG_VER} 不一致"; fi
if [ "$CLI_VER" = "$CHANGELOG_VER" ]; then ok "apps/cli/package.json 版本一致: $CLI_VER（pod --version 会打这个）"
else bad "apps/cli/package.json 是 ${CLI_VER}，但 CHANGELOG 是 ${CHANGELOG_VER}（pod --version 会报错版本）"; fi
# 发布 tag 必须已存在（钉版本的前提）
if git rev-parse -q --verify "refs/tags/$CHANGELOG_VER" >/dev/null; then ok "本地存在 tag $CHANGELOG_VER"
else bad "本地没有 tag ${CHANGELOG_VER}——安装链接会 404"; fi

# ── 2. 内容稿的静态一致性 ───────────────────────────────────────────────────
step "2. 内容稿：占位符 / 旧编号 / 失效命令 / 钉版本安装链接"
for pat in "TODO" "待补" "XXX" "AG-0" "github.com/podsec" "npm i -g @podsec"; do
  hits="$(grep -rn "$pat" docs/content/ 2>/dev/null | wc -l | tr -d ' ')"
  if [ "$hits" = "0" ]; then ok "无「${pat}」"
  else bad "命中「${pat}」${hits} 处：$(grep -rln "$pat" docs/content/ | tr '\n' ' ')"; fi
done
missing_link=0
for f in docs/content/[0-9]*.md; do
  grep -q "raw/$CHANGELOG_VER/scripts/install.sh" "$f" || { bad "${f} 缺钉版本的安装链接"; missing_link=1; }
done
[ "$missing_link" = "0" ] && ok "每篇内容都有钉在 $CHANGELOG_VER 的安装命令"

# ── 3. 内容稿里的 pod 子命令是否真实存在 ────────────────────────────────────
step "3. 内容稿引用的 pod 子命令都在 CLI 里"
if [ -f apps/cli/dist/index.js ]; then
  HELP="$(node apps/cli/dist/index.js --help 2>&1)"
  UNKNOWN=0
  # 只从**代码块**里取命令：否则英文正文里的 "pod writes the rules…" 会被当成子命令
  for cmd in $(awk '/^```/{f=!f; next} f' docs/content/*.md docs/content/publish/*.md 2>/dev/null \
      | grep -oE '(^|[[:space:]])(\$ )?pod [a-z][a-z-]+' | awk '{print $NF}' | sort -u); do
    if echo "$HELP" | grep -qE "(^| )$cmd(\$| )" || echo "$HELP" | grep -q "pod $cmd"; then :; else
      bad "内容里出现未知子命令: pod ${cmd}"; UNKNOWN=1
    fi
  done
  [ "$UNKNOWN" = "0" ] && ok "引用的子命令全部存在"
else
  warn "未构建 CLI（先 pnpm build），跳过子命令校验"
fi

# ── 4. 链接可达 ─────────────────────────────────────────────────────────────
step "4. 内容里的外链可达"
# 取 HTTP 状态码：失败时给 000，不要把 curl 的退出码拼进状态码里
http_code() {
  local c
  c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -L "$1" 2>/dev/null)"
  [ -n "$c" ] && printf '%s' "$c" || printf '000'
}
check_url() { # $1=url  $2=fail_on_404(1/0)
  local url="$1" code
  code="$(http_code "$url")"
  if [ "$code" = "000" ]; then                    # 网络问题，重试一次再判断
    sleep 2
    code="$(http_code "$url")"
  fi
  case "$code" in
    200) ok "$url" ;;
    404) bad "$url → HTTP 404（链接真的坏了）" ;;
    000) warn "$url → 连不上（多为网络/被限流，非内容问题；换网络重跑一次）" ;;
    *)   warn "$url → HTTP ${code}（非 404，人工确认）" ;;
  esac
}
for url in $(grep -rhoE 'https://(gitee\.com|github\.com|raw\.githubusercontent\.com)/[A-Za-z0-9_./-]+' docs/content/ README.md | sort -u | head -10); do
  check_url "$url"
done

# ── 5. 发布版安装脚本 URL 可达（主源 + 镜像）────────────────────────────────
step "5. 发布版安装脚本 URL 可达（主源 + 镜像）"
check_url "https://gitee.com/suhuisoftwares/pod/raw/$CHANGELOG_VER/scripts/install.sh"
check_url "https://raw.githubusercontent.com/suhui-organization/pod/$CHANGELOG_VER/scripts/install.sh"

# ── 6. 干净环境安装 + 主路径冒烟 ────────────────────────────────────────────
step "6. 干净环境安装 + 主路径冒烟"
if [ "$QUICK" = "1" ]; then
  warn "已跳过（--quick）"
else
  T="$(mktemp -d)"
  if POD_SRC="$T/src" POD_BIN_DIR="$T/bin" bash scripts/install.sh >"$T/install.log" 2>&1; then
    ok "安装成功（$T/bin/pod）"
    export PATH="$T/bin:$PATH" HOME="$T/home"; mkdir -p "$HOME"
    if pod init --template baseline >/dev/null 2>&1 \
      && pod ingest --agent ci --server filesystem --tool read_file --decision allow --outcome ok --args '{"path":"/tmp/x"}' >/dev/null \
      && pod policy draft --out "$HOME/draft.json" >/dev/null \
      && pod verify-audit >/dev/null 2>&1 \
      && pod posture freeze >/dev/null 2>&1 \
      && pod identity init --agent ci >/dev/null 2>&1; then
      ok "主路径冒烟通过（init → ingest → policy draft → verify-audit → posture → identity）"
    else
      bad "主路径冒烟失败（看 $T/install.log）"
    fi
  else
    bad "安装失败：tail -20 $T/install.log"
  fi
fi

# ── 7. 云端一键部署的静态检查 ───────────────────────────────────────────────
step "7. 云端一键部署（静态）"
[ -f deploy/install.sh ] && ok "deploy/install.sh 存在" || bad "缺 deploy/install.sh"
[ -f deploy/docker-compose.yml ] && ok "deploy/docker-compose.yml 存在" || bad "缺 docker-compose.yml"
for p in ../cloud/server ../cloud/web; do
  grep -q "$p" deploy/docker-compose.yml && ok "compose 构建上下文 $p" || bad "compose 里找不到 $p"
done
[ -f cloud/server/app/main.py ] && ok "云端后端源码在 cloud/server" || bad "缺 cloud/server/app/main.py"
[ -f cloud/web/package.json ] && ok "云端前端源码在 cloud/web" || bad "缺 cloud/web/package.json"

# ── 8. 赞助入口（FUNDING.yml ↔ README 必须指向同一个账号）───────────────────
# 这一项跟 1. 是同一类问题：两处要一起改。FUNDING.yml 写 A、README 写 B，
# 仓库右上角按钮跳 A、文章里点进去是 B——两边都"看起来对"。
step "8. 赞助入口一致（FUNDING.yml ↔ README）"
if [ -f .github/FUNDING.yml ]; then
  ok ".github/FUNDING.yml 存在"
  SPONSOR_ACCOUNT="$(sed -n 's/^github:[[:space:]]*\[\([^]]*\)\].*/\1/p' .github/FUNDING.yml | head -1 | tr -d '[:space:]')"
  if [ -n "$SPONSOR_ACCOUNT" ]; then
    ok "FUNDING.yml 指向 github: $SPONSOR_ACCOUNT"
    # README 里至少要有一条指向 github.com/sponsors/<同一账号> 的链接
    if grep -q "github.com/sponsors/$SPONSOR_ACCOUNT" README.md; then
      ok "README 的赞助链接指向同一账号"
    else
      bad "README 里没有 github.com/sponsors/$SPONSOR_ACCOUNT 的链接（两处账号不一致？）"
    fi
  else
    bad "FUNDING.yml 里没有 github: 条目（Sponsor 按钮不会出现，而且是静默的）"
  fi
else
  bad "缺 .github/FUNDING.yml（仓库页不会出现 Sponsor 按钮）"
fi

# ── 9. 双远端镜像一致（Gitee = GitHub 的只读镜像）────────────────────────────
# 为什么需要这条：GitHub 那边有分支保护兜着（必须 PR + CI），Gitee 这边**免费版
# 开不了保护分支**（付费功能），所以"不许直接推 Gitee main"只能靠纪律 —— 纪律要
# 有可验证的落点，就是这条：两端 main 必须指向同一个提交，出现漂移说明有人绕过了流程。
step "9. 双远端镜像一致（GitHub = Gitee）"
MIRROR_GH="$(git ls-remote github refs/heads/main 2>/dev/null | cut -f1)"
MIRROR_GE="$(git ls-remote gitee refs/heads/main 2>/dev/null | cut -f1)"
GH7="$(printf '%s' "$MIRROR_GH" | cut -c1-7)"
GE7="$(printf '%s' "$MIRROR_GE" | cut -c1-7)"
if [ -z "$MIRROR_GH" ] || [ -z "$MIRROR_GE" ]; then
  # 取不到不等于漂移（网络抖动很常见，GitHub 尤其），但要说出来，别让人以为查过了
  warn "远端取不到（github=${MIRROR_GH:-不可达} gitee=${MIRROR_GE:-不可达}）——本次跳过镜像比对"
elif [ "$MIRROR_GH" = "$MIRROR_GE" ]; then
  ok "两端 main 同源：${GH7}"
else
  bad "main 不一致：github=${GH7} gitee=${GE7}——Gitee 是只读镜像，出现漂移说明有人绕过了流程"
  echo "     对齐：git push gitee github/main:main（或反过来，先确认哪边是对的）"
fi

# ── 汇总 ────────────────────────────────────────────────────────────────────
echo
if [ "$FAIL" = "0" ]; then
  echo -e "${GREEN}发布预检通过${NC}（$PASS 项）"
  exit 0
fi
echo -e "${RED}发布预检未通过：$FAIL 项待处理${NC}（通过 $PASS 项）"
exit 1
