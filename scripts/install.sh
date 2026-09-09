#!/usr/bin/env bash
# ============================================================================
# install.sh — pod 一键安装（从源码构建，无需 npm 账号）
#
#   curl -fsSL https://gitee.com/suhuisoftwares/pod/raw/main/scripts/install.sh | sh
#
# 做了什么：
#   1. 检查 Node.js >= 20 与 git
#   2. 克隆/更新源码到 ~/.pod/src
#   3. pnpm install + build
#   4. 把可执行文件装到 ~/.local/bin/pod（可用环境变量覆盖）
#
# 环境变量：
#   POD_REPO_URL   源码地址（默认 Gitee；可指向本地路径做离线安装）
#   POD_VERSION    分支/标签（默认 main）
#   POD_SRC        源码目录（默认 ~/.pod/src）
#   POD_BIN_DIR    可执行文件目录（默认 ~/.local/bin）
# ============================================================================
set -euo pipefail

POD_REPO_URL="${POD_REPO_URL:-https://gitee.com/suhuisoftwares/pod.git}"
POD_VERSION="${POD_VERSION:-main}"
POD_SRC="${POD_SRC:-$HOME/.pod/src}"
POD_BIN_DIR="${POD_BIN_DIR:-$HOME/.local/bin}"

fail() { printf 'pod install: %s\n' "$*" >&2; exit 1; }
info() { printf '  %s\n' "$*"; }

command -v node >/dev/null 2>&1 || fail "需要 Node.js >= 22.13（未找到 node）"
command -v git  >/dev/null 2>&1 || fail "需要 git"
NODE_VERSION="$(node -p 'process.versions.node')"
node -e "const [maj,min]=process.versions.node.split('.').map(Number); process.exit(maj>22 || (maj===22 && min>=13) ? 0 : 1)" \
  || fail "需要 Node.js >= 22.13（pnpm 11 要求），当前 v$NODE_VERSION"

if command -v pnpm >/dev/null 2>&1; then
  PNPM=(pnpm)
elif command -v corepack >/dev/null 2>&1; then
  PNPM=(corepack pnpm)
else
  PNPM=(npx --yes pnpm@11.7.0)
fi

if [ -d "$POD_SRC/.git" ]; then
  info "更新源码: $POD_SRC"
  git -C "$POD_SRC" fetch --depth 1 origin "$POD_VERSION"
  git -C "$POD_SRC" checkout -q FETCH_HEAD
else
  info "克隆源码: $POD_REPO_URL → $POD_SRC"
  mkdir -p "$(dirname "$POD_SRC")"
  git clone --depth 1 --branch "$POD_VERSION" "$POD_REPO_URL" "$POD_SRC"
fi

info "安装依赖并构建（首次约 1-2 分钟）"
(cd "$POD_SRC" && "${PNPM[@]}" install --frozen-lockfile && "${PNPM[@]}" build)

mkdir -p "$POD_BIN_DIR"
cat > "$POD_BIN_DIR/pod" <<EOF
#!/usr/bin/env bash
exec node "$POD_SRC/apps/cli/dist/index.js" "\$@"
EOF
chmod +x "$POD_BIN_DIR/pod"

"$POD_BIN_DIR/pod" --help >/dev/null 2>&1 || fail "安装后自检失败，请到 $POD_SRC 手动运行 pnpm build 查看错误"
info "已安装: $POD_BIN_DIR/pod"

case ":$PATH:" in
  *":$POD_BIN_DIR:"*) ;;
  *)
    printf '\n把下面这行加到 shell 配置（~/.zshrc 或 ~/.bashrc）后重开终端:\n'
    printf '  export PATH="%s:$PATH"\n' "$POD_BIN_DIR"
    ;;
esac

printf '\n完成。验证: pod --help\n'
