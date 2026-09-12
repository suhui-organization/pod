#!/usr/bin/env bash
# ============================================================================
# install-local.sh — Pod Cloud 本地 k8s 完整安装路径（幂等，可反复执行）
#
# 一条命令完成: 环境预检 → 构建镜像 → 载入 kind → 渲染清单(注入 tag/密钥)
#   → 应用 → 等待就绪 → web 端口暴露 → 健康验证 → (可选)管理员引导
#
# 用法:
#   bash install-local.sh
#   IMAGE_TAG=0.1.18 ADMIN_EMAIL=admin@x.com ADMIN_PASSWORD=xxx bash install-local.sh
#
# 环境变量(全部可选):
#   IMAGE_TAG        显式指定镜像 tag（默认按源码内容指纹自动生成 fp-<hash>，
#                    server/web 各自独立；内容变化自动换 tag，kubelet 必然拉新）
#   WEB_PORT_FWD     本地访问端口（默认 18088）
#   PUBLIC_BASE_URL  后端对外地址（默认 http://127.0.0.1:18088）
#   KIND_CLUSTER     kind 集群名（默认自动探测，恰好一个时使用；kind 不可用时跳过 load）
#   SERVER_REPO      server 源码根（默认本脚本位置 ../..，即 cloud/server）
#   WEB_REPO         web 源码根（默认 <SERVER_REPO>/../web，即 cloud/web）
#   ADMIN_EMAIL      设置后自动创建管理员（已存在则跳过）
#   ADMIN_PASSWORD   同上（与 ADMIN_EMAIL 成对）
#   FORCE_BUILD=1    即使源码指纹未变化也强制重建
#   STAMP_DIR        构建指纹目录（默认 ~/.cache/podcloud；用于判断源码是否变化）
#
# 行为: 每次运行比对源码内容指纹——变了才重建镜像 + kind load + 滚动重启；
#       没变则全链路幂等空跑（仍做健康验证）。无需手工 rollout。
# 卸载: kubectl delete ns podcloud
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_REPO="${SERVER_REPO:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
WEB_REPO="${WEB_REPO:-$SERVER_REPO/../web}"
NS="podcloud"
IMAGE_TAG="${IMAGE_TAG:-}"
WEB_PORT_FWD="${WEB_PORT_FWD:-18088}"
PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-http://127.0.0.1:${WEB_PORT_FWD}}"
RENDER_DIR="${PODCLOUD_RENDER_DIR:-/tmp/podcloud-k8s-rendered}"
PF_PID_FILE="/tmp/podcloud-port-forward.pid"
STAMP_DIR="${STAMP_DIR:-$HOME/.cache/podcloud}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'
ok()  { echo -e "${GREEN}[ok]${NC}   $*"; }
warn(){ echo -e "${YELLOW}[warn]${NC} $*"; }
fail(){ echo -e "${RED}[fail]${NC} $*" >&2; exit 1; }
step(){ echo; echo -e "${GREEN}── $*${NC}"; }

# ── 0. 工具与路径预检 ───────────────────────────────────────────────────────
step "0/7 工具预检"
for tool in docker kubectl curl openssl python3; do
  command -v "$tool" >/dev/null 2>&1 || fail "缺少依赖工具: $tool"
done
[ -f "$SERVER_REPO/deploy/Dockerfile" ] || fail "找不到 server 构建文件: $SERVER_REPO/deploy/Dockerfile（可用 SERVER_REPO 指定）"
[ -f "$WEB_REPO/deploy/Dockerfile" ]    || fail "找不到 web 构建文件: $WEB_REPO/deploy/Dockerfile（可用 WEB_REPO 指定）"
kubectl cluster-info >/dev/null 2>&1 || fail "kubectl 无法连接集群（先启动 kind / 检查 KUBECONFIG）"
kubectl get storageclass standard >/dev/null 2>&1 \
  || warn "集群无 standard StorageClass——PVC podcloud-data 将无法绑定"
ok "工具与仓库路径就绪"

# ── 1. kind 集群识别（决定能否 load 镜像）────────────────────────────────────
step "1/7 集群识别"
KIND_NAME=""
if command -v kind >/dev/null 2>&1; then
  if [ -n "${KIND_CLUSTER:-}" ]; then
    KIND_NAME="$KIND_CLUSTER"
  else
    n="$(kind get clusters 2>/dev/null | grep -v '^$' | wc -l | tr -d ' ')"
    if [ "$n" = "1" ]; then KIND_NAME="$(kind get clusters | grep -v '^$')"; fi
  fi
  if [ -n "$KIND_NAME" ]; then
    kind get nodes --name "$KIND_NAME" >/dev/null 2>&1 || fail "kind 集群 '$KIND_NAME' 不存在（kind get clusters 查看）"
    ok "kind 集群: $KIND_NAME"
  else
    warn "kind 可用但集群不唯一/为空: 跳过镜像载入，请自行 kind load（或用 KIND_CLUSTER 指定）"
  fi
else
  warn "未安装 kind CLI: 跳过镜像载入，请自行把镜像导入节点（kind load / ctr -n k8s.io images import）"
fi

# ── 2. 构建镜像（源码内容指纹 → 内容寻址 tag）──────────────────────────────
step "2/7 构建镜像 (源码指纹 → 内容 tag)"
mkdir -p "$STAMP_DIR"
REBUILT=()
# 镜像输入指纹: 只统计真正进入镜像的文件(改 deploy/k8s 脚本等不会误触发重建)
source_fp() { # $1=repo  $2=server|web
  local repo="$1" kind="$2"
  if [ "$kind" = "server" ]; then
    # server Dockerfile 只 COPY: requirements.txt + app/ + scripts/
    # xargs 必须留在子 shell 内：放到外面会在脚本当前目录执行，找不到这些相对路径
    ( cd "$repo" && printf '%s\0' deploy/Dockerfile requirements.txt \
      && find app scripts -type f ! -path '*/__pycache__/*' ! -name '*.pyc' -print0 \
      | sort -z | xargs -0 sha256sum ) | sha256sum | cut -d' ' -f1
  else
    ( cd "$repo" && find . -type f \
        ! -path './.git/*' ! -path '*/node_modules/*' ! -path '*/dist/*' \
        ! -path '*/__pycache__/*' ! -name '*.pyc' ! -name '*.pyo' \
        -print0 | sort -z | xargs -0 sha256sum ) | sha256sum | cut -d' ' -f1
  fi
}
# 内容寻址 tag：内容变 → tag 变 → kubelet 必然拉新（同 tag 缓存问题的根因修复）
SERVER_FP="$(source_fp "$SERVER_REPO" server)"
WEB_FP="$(source_fp "$WEB_REPO" web)"
if [ -n "$IMAGE_TAG" ]; then
  SERVER_IMAGE_TAG="$IMAGE_TAG"; WEB_IMAGE_TAG="$IMAGE_TAG"
  echo "  显式 IMAGE_TAG=${IMAGE_TAG}（server/web 共用；同 tag 重建仍需滚动重启）"
else
  SERVER_IMAGE_TAG="fp-${SERVER_FP:0:12}"
  WEB_IMAGE_TAG="fp-${WEB_FP:0:12}"
fi
build_image() { # $1=repo $2=镜像名 $3=server|web $4=tag $5=content_fp
  local repo="$1" name="$2" kind="$3" tag="$4" fp="$5" stamp
  stamp="$STAMP_DIR/${name}.content.fp"
  if [ "${FORCE_BUILD:-0}" = "1" ]; then
    echo "  FORCE_BUILD=1 → 强制重建 $name"
  elif [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$fp" ] \
    && docker image inspect "$name:$tag" >/dev/null 2>&1; then
    ok "内容未变且镜像已存在: $name:${tag}（跳过构建）"
    return 0
  else
    echo "  检测到新内容 → 构建 $name:$tag ..."
  fi
  ( cd "$repo" && docker build -f deploy/Dockerfile -t "$name:$tag" . ) || fail "构建 $name 失败"
  printf '%s' "$fp" > "$stamp"
  REBUILT+=("$name")
  ok "构建完成: $name:$tag"
}
build_image "$SERVER_REPO" podcloud-server server "$SERVER_IMAGE_TAG" "$SERVER_FP"
build_image "$WEB_REPO"    podcloud-web    web    "$WEB_IMAGE_TAG"    "$WEB_FP"

if [ -n "$KIND_NAME" ]; then
  step "2b/7 载入镜像到 kind($KIND_NAME)"
  kind load docker-image "podcloud-server:$SERVER_IMAGE_TAG" "podcloud-web:$WEB_IMAGE_TAG" --name "$KIND_NAME" || fail "kind load 失败"
  ok "镜像已载入节点"
fi

# ── 3. 渲染清单（注入 tag；密钥复用或新建）───────────────────────────────────
step "3/7 渲染清单"
rm -rf "$RENDER_DIR"; mkdir -p "$RENDER_DIR"; chmod 700 "$RENDER_DIR"
for f in "$SCRIPT_DIR"/*.yaml; do
  sed -e "s/__SERVER_IMAGE_TAG__/$SERVER_IMAGE_TAG/g" \
      -e "s/__WEB_IMAGE_TAG__/$WEB_IMAGE_TAG/g" \
      -e "s#value: \"http://127.0.0.1:18088\"#value: \"$PUBLIC_BASE_URL\"#" \
      "$f" > "$RENDER_DIR/$(basename "$f")"
done

# 先让 namespace 存在，再决定密钥：集群已有则复用（避免每次重装轮换 JWT 导致登录失效）
kubectl apply -f "$RENDER_DIR/00-namespace.yaml" >/dev/null
EXISTING="$(kubectl -n "$NS" get secret podcloud-secrets -o jsonpath='{.data.PODCLOUD_JWT_SECRET}' 2>/dev/null || true)"
if [ -n "$EXISTING" ]; then
  SECRET="$(printf '%s' "$EXISTING" | base64 -d)"
  ok "复用集群内现有 JWT Secret（不轮换）"
else
  SECRET="$(openssl rand -hex 32)"
  ok "生成新 JWT Secret"
fi
# 可移植写法：macOS 自带 BSD sed 不支持 GNU 的 `sed -i`（必须给备份后缀）
tmp_secret="$(mktemp)"
sed "s/__JWT_SECRET__/$SECRET/g" "$RENDER_DIR/02-secret.yaml" > "$tmp_secret"
mv "$tmp_secret" "$RENDER_DIR/02-secret.yaml"

# 计费配置（Paddle 等）：取值优先级 = 本次调用的环境变量 > 集群里已有的值 > 留空。
#   PADDLE_API_KEY=... bash install-local.sh        # 首次写入
#   bash install-local.sh                            # 之后复用，不会被清掉
# 留空是安全的：服务端把"没有计费配置"当未开通处理（billing_configured=false）。
for key in PODCLOUD_BILLING_PROVIDER PADDLE_API_KEY PADDLE_WEBHOOK_SECRET \
           PADDLE_PRICE_PRO PADDLE_CLIENT_TOKEN PADDLE_ENV; do
  val="${!key:-}"
  if [ -z "$val" ]; then
    cur="$(kubectl -n "$NS" get secret podcloud-secrets -o jsonpath="{.data.$key}" 2>/dev/null || true)"
    [ -n "$cur" ] && val="$(printf '%s' "$cur" | base64 -d || true)"
  fi
  if [ -z "$val" ] && [ "$key" = "PADDLE_ENV" ]; then
    val="sandbox"   # 默认打 sandbox：配错也只是测试环境，不会误扣真钱
  fi
  tmp_secret="$(mktemp)"
  sed "s|__${key}__|$val|g" "$RENDER_DIR/02-secret.yaml" > "$tmp_secret"
  mv "$tmp_secret" "$RENDER_DIR/02-secret.yaml"
done
if [ -n "${PADDLE_API_KEY:-}" ]; then
  ok "计费配置已注入（provider=${PODCLOUD_BILLING_PROVIDER:-paddle}, env=${PADDLE_ENV:-sandbox}）"
else
  warn "未提供 PADDLE_* 环境变量——沿用集群已有值；首次部署则计费保持未开通"
fi

# 校验渲染后无残留占位符
grep -rn "__SERVER_IMAGE_TAG__\|__WEB_IMAGE_TAG__\|__JWT_SECRET__\|__PADDLE\|__PODCLOUD_BILLING" "$RENDER_DIR" \
  && fail "渲染残留占位符，已中止" || true
ok "清单渲染完成: $RENDER_DIR"

# ── 4. 应用清单;同 tag 重建后自动滚动重启;运行态 sha 兜底比对 ─────────────
step "4/7 应用清单 (ns=$NS)"
kubectl apply -f "$RENDER_DIR/01-pvc.yaml" >/dev/null
kubectl apply -f "$RENDER_DIR/02-secret.yaml" >/dev/null
kubectl apply -f "$RENDER_DIR/03-deployment-server.yaml" >/dev/null
kubectl apply -f "$RENDER_DIR/04-service-server.yaml" >/dev/null
kubectl apply -f "$RENDER_DIR/05-deployment-web.yaml" >/dev/null
kubectl apply -f "$RENDER_DIR/06-service-web.yaml" >/dev/null

RESTART_NEEDED=()
# 同 tag 重建: kubelet 按 tag 命中旧层缓存,必须显式滚动重启才会拉新内容;
# 指纹未变说明内容一致 → 不重启(幂等空跑)。不引入 sha 比对: 本地 docker
# config 摘要与节点 containerd import 摘要体系不同,比对必然误报。
for d in "${REBUILT[@]:-}"; do
  [ -n "$d" ] || continue
  RESTART_NEEDED+=("$d")
  ok "镜像已重建($d) → 滚动重启"
done
if [ "${#RESTART_NEEDED[@]}" -gt 0 ]; then
  # 顺序不能省：web 的新版本会调用服务端新增的端点（规则包 / 加固报告 / 熔断）。
  # 两个 Deployment 一起 restart 会出现"新前端 + 旧后端"的窗口，新页面临时 404。
  # 所以先把 server 滚完并等它就绪，再滚 web。
  for d in "${RESTART_NEEDED[@]}"; do
    [ "$d" = "podcloud-server" ] || continue
    kubectl -n "$NS" rollout restart "deploy/$d" >/dev/null
    kubectl -n "$NS" rollout status  "deploy/$d" --timeout=300s
  done
  for d in "${RESTART_NEEDED[@]}"; do
    [ "$d" = "podcloud-web" ] || continue
    kubectl -n "$NS" rollout restart "deploy/$d" >/dev/null
  done
fi
kubectl -n "$NS" rollout status deploy/podcloud-server --timeout=300s
kubectl -n "$NS" rollout status deploy/podcloud-web    --timeout=300s
ok "两个 Deployment 均就绪（本轮重建/重启: ${RESTART_NEEDED[*]:-无}）"

# ── 5. web 端口暴露（已在监听则跳过）───────────────────────────────────────
step "5/7 端口暴露 127.0.0.1:${WEB_PORT_FWD}"
if curl -fsS --max-time 3 "http://127.0.0.1:${WEB_PORT_FWD}/healthz" >/dev/null 2>&1; then
  ok "端口已在转发，复用现有通道"
else
  if [ -f "$PF_PID_FILE" ] && kill -0 "$(cat "$PF_PID_FILE")" 2>/dev/null; then
    kill "$(cat "$PF_PID_FILE")" 2>/dev/null || true
  fi
  nohup kubectl -n "$NS" port-forward "svc/podcloud-web" "${WEB_PORT_FWD}:80" \
    >"$RENDER_DIR/port-forward.log" 2>&1 &
  echo "$!" > "$PF_PID_FILE"
  for i in $(seq 1 20); do
    curl -fsS --max-time 2 "http://127.0.0.1:${WEB_PORT_FWD}/healthz" >/dev/null 2>&1 && break
    sleep 1
  done
  curl -fsS --max-time 3 "http://127.0.0.1:${WEB_PORT_FWD}/healthz" >/dev/null 2>&1 \
    || fail "端口转发未就绪（日志: $RENDER_DIR/port-forward.log）"
  ok "端口转发已启动 (pid $(cat "$PF_PID_FILE"))"
fi

# ── 6. 健康验证（全链路） ───────────────────────────────────────────────────
step "6/7 健康验证"
# 滚动刚结束时 web→server 上游可能瞬时 502，重试最多 10s 再判定失败
code_root=""; cfg=""
for _ in $(seq 1 10); do
  code_root="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${WEB_PORT_FWD}/" || true)"
  cfg="$(curl -fsS --max-time 3 "http://127.0.0.1:${WEB_PORT_FWD}/api/v1/auth/config" 2>/dev/null || true)"
  if [ "$code_root" = "200" ] && echo "$cfg" | grep -q is_private; then break; fi
  sleep 1
done
[ "$code_root" = "200" ] || fail "web 首页返回 $code_root"
echo "$cfg" | grep -q is_private || fail "API 反代异常: $cfg"
ok "web=$code_root | API=$cfg"

# ── 7. (可选)管理员引导 ─────────────────────────────────────────────────────
step "7/7 管理员引导"
if [ -n "${ADMIN_EMAIL:-}" ] && [ -n "${ADMIN_PASSWORD:-}" ]; then
  code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${WEB_PORT_FWD}/api/v1/auth/register" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\",\"full_name\":\"本地管理员\",\"client\":\"web\"}")"
  if [ "$code" = "201" ] || [ "$code" = "200" ]; then
    ok "管理员已创建: $ADMIN_EMAIL"
  elif [ "$code" = "409" ]; then
    ok "管理员已存在: ${ADMIN_EMAIL}（跳过创建）"
  else
    warn "注册返回 ${code}（私有模式或异常，请手动在页面注册）"
  fi
else
  warn "未设置 ADMIN_EMAIL/ADMIN_PASSWORD——跳过管理员引导（公开模式下可在页面自助注册）"
fi

echo
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Pod Cloud 本地部署完成${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo "  访问地址 : http://127.0.0.1:${WEB_PORT_FWD}"
echo "  命名空间 : $NS (卸载: kubectl delete ns $NS)"
echo "  镜像 tag : server=$SERVER_IMAGE_TAG web=${WEB_IMAGE_TAG}（内容指纹自动生成）"
echo "  指纹目录 : $STAMP_DIR (删除某镜像的 .fp 可触发其重建)"
echo "  下一步   : 在页面注册 agent，或运行 agent 侧完整脚本:"
echo "             bash <pod 仓库>/scripts/setup-agent.sh \\"
echo "               ADMIN_EMAIL=... ADMIN_PASSWORD=...   # 全自动注册+接入+同步"
echo "  端口转发 : pid=$(cat "$PF_PID_FILE" 2>/dev/null || echo '-') (kill 结束转发)"
