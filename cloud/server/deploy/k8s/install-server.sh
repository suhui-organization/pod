#!/usr/bin/env bash
# ============================================================================
# install-server.sh — Pod Cloud 服务器集群的构建 + 滚动发布
#
# 与 install-local.sh 的分工（两条路必须分开，别互相套用）:
#   install-local.sh   本机 kind：内容指纹 tag → kind load → apply 仓库里的渲染清单
#   install-server.sh  服务器集群：commit tag → 在节点就地构建 → 导入 containerd
#                      → set image 滚动
#
# 为什么服务器这条路要单独一个脚本:
#   1. 集群没有可达的公网镜像仓，而 **docker 里的镜像 kubelet 看不见**——
#      必须 `docker save | ctr -n k8s.io images import -` 灌进 k8s 的 containerd；
#   2. 服务器上的清单是手工调过的（nodeSelector→hadoop8、hostPath PV、
#      NodePort 30088、server 用 Recreate 因为 SQLite 不能被两个 Pod 同时写），
#      **不能被仓库模板覆盖**，所以这里只做外科手术式的 set image，不 apply 清单；
#   3. 发布顺序是硬约束：server 先滚完并就绪，再滚 web。
#
# 用法:
#   KUBECONFIG=~/.kube/config-server.yaml bash install-server.sh
#   GIT_REF=main bash install-server.sh                  # 指定要发布的 ref
#   SKIP_BUILD=1 IMAGE_TAG=main-fbf730b bash install-server.sh   # 镜像已在节点，只滚动
#   DRY_RUN=1 bash install-server.sh                     # 只打印计划，不改任何东西
#   LOCAL_BUILD=1 bash install-server.sh                 # 代码还没 push？在本机构建再流式导入节点
#
# 环境变量(全部可选):
#   KUBECONFIG    默认 ~/.kube/config-server.yaml（存在时）
#   NAMESPACE     默认 podcloud
#   GIT_REF       默认 main
#   IMAGE_TAG     默认 main-<目标 commit 短 sha>（内容变了 tag 就变，可追溯）
#   BUILD_DIR     节点上的源码目录，默认 /opt/podcloud-build/pod
#   SSH_USER      默认 root
#   NO_BACKUP=1   跳过发布前的数据库备份（不建议）
#   SKIP_VERIFY=1 跳过发布后的健康验证
#   DRY_RUN=1     只打印计划
#   LOCAL_BUILD=1 从**本机 HEAD** 构建（默认从节点的 origin/<GIT_REF> 构建）
# ============================================================================
set -euo pipefail

NS="${NAMESPACE:-podcloud}"
GIT_REF="${GIT_REF:-main}"
BUILD_DIR="${BUILD_DIR:-/opt/podcloud-build/pod}"
SSH_USER="${SSH_USER:-root}"
IMAGE_TAG="${IMAGE_TAG:-}"
LOCAL_BUILD="${LOCAL_BUILD:-0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

if [ -z "${KUBECONFIG:-}" ] && [ -r "$HOME/.kube/config-server.yaml" ]; then
  export KUBECONFIG="$HOME/.kube/config-server.yaml"
fi

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'
ok()  { echo -e "${GREEN}[ok]${NC}   $*"; }
warn(){ echo -e "${YELLOW}[warn]${NC} $*"; }
fail(){ echo -e "${RED}[fail]${NC} $*" >&2; exit 1; }
step(){ echo; echo -e "${GREEN}── $*${NC}"; }
run_or_print() { # DRY_RUN 下只打印
  if [ "${DRY_RUN:-0}" = "1" ]; then echo "   [dry-run] $*"; else "$@"; fi
}
ssh_node() { ssh -o BatchMode=yes -o ConnectTimeout=8 "${SSH_USER}@${NODE_IP}" "$@"; }

# ── 0. 预检 ────────────────────────────────────────────────────────────────
step "0/6 预检"
for tool in kubectl ssh; do command -v "$tool" >/dev/null 2>&1 || fail "缺少依赖工具: $tool"; done
kubectl get nodes >/dev/null 2>&1 || fail "kubectl 连不上集群（检查 KUBECONFIG=$KUBECONFIG）"
kubectl -n "$NS" get deploy podcloud-server >/dev/null 2>&1 || fail "命名空间 $NS 里没有 podcloud-server"

# 构建节点 = Deployment 上 nodeSelector 指定的那台（避免"构建机"与"运行机"不是同一台）
NODE_NAME="$(kubectl -n "$NS" get deploy podcloud-server \
  -o jsonpath='{.spec.template.spec.nodeSelector.kubernetes\.io/hostname}' 2>/dev/null || true)"
[ -n "$NODE_NAME" ] || fail "podcloud-server 没有 nodeSelector.kubernetes.io/hostname——无法确定构建节点"
NODE_IP="$(kubectl get node "$NODE_NAME" \
  -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || true)"
[ -n "$NODE_IP" ] || fail "拿不到节点 $NODE_NAME 的 InternalIP"
ssh_node true >/dev/null 2>&1 || fail "ssh ${SSH_USER}@${NODE_IP} 不通（脚本要在该节点上构建镜像）"
ssh_node 'command -v docker >/dev/null && command -v ctr >/dev/null && command -v git >/dev/null' \
  || fail "节点缺 docker / ctr / git"

STRATEGY="$(kubectl -n "$NS" get deploy podcloud-server -o jsonpath='{.spec.strategy.type}')"
ok "集群 / 命名空间 / 构建节点就绪: ${NODE_NAME}(${NODE_IP})"
echo "     server 发布策略: ${STRATEGY}$([ "$STRATEGY" = "Recreate" ] && echo "（先停旧再起新：会有几十秒 API 不可用）")"

# ── 1. 解析目标 commit，并说清这次到底改了什么 ──────────────────────────────
step "1/6 解析目标版本（$GIT_REF）"
if [ "$LOCAL_BUILD" = "1" ]; then
  # 代码还没 push 时的路径：从本机 HEAD 构建。tag 仍然指向一个真实的 commit，
  # 只是这个 commit 尚未出现在 origin 上——推送之后它就自动可追溯了。
  command -v docker >/dev/null 2>&1 || fail "LOCAL_BUILD=1 需要本机有 docker"
  TARGET_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null)" || fail "从 $REPO_ROOT 读不到 HEAD"
  DIRTY="$(git -C "$REPO_ROOT" status --porcelain -- cloud/server cloud/web 2>/dev/null || true)"
  [ -z "$DIRTY" ] || warn "本机构建：cloud/ 下还有未提交改动，镜像内容与 commit 不完全一致"
else
  ssh_node "cd '$BUILD_DIR' && git fetch -q origin '$GIT_REF' && git rev-parse FETCH_HEAD" \
    > /tmp/.podcloud-target-sha || fail "在节点上 fetch $GIT_REF 失败"
  TARGET_SHA="$(cat /tmp/.podcloud-target-sha)"
fi
TARGET_SHORT="$(printf '%s' "$TARGET_SHA" | cut -c1-7)"
[ -n "$IMAGE_TAG" ] || IMAGE_TAG="main-${TARGET_SHORT}"
ok "目标 commit: ${TARGET_SHORT}（镜像 tag: ${IMAGE_TAG}）"

# 运行中的 tag 形如 main-4ba4f91：取后半段当 sha，用来算差异
RUN_SERVER_IMG="$(kubectl -n "$NS" get deploy podcloud-server -o jsonpath='{.spec.template.spec.containers[0].image}')"
RUN_WEB_IMG="$(kubectl -n "$NS" get deploy podcloud-web -o jsonpath='{.spec.template.spec.containers[0].image}')"
echo "     当前运行: server=${RUN_SERVER_IMG} web=${RUN_WEB_IMG}"

diff_since() { # $1=运行中的 tag  $2=子路径
  local from_sha="${1##*main-}"
  [ -n "$from_sha" ] || return 0
  if [ "$LOCAL_BUILD" = "1" ]; then
    git -C "$REPO_ROOT" cat-file -e "${from_sha}^{commit}" 2>/dev/null \
      && git -C "$REPO_ROOT" diff --stat "$from_sha" "$TARGET_SHA" -- "$2" | tail -1
  else
    ssh_node "cd '$BUILD_DIR' && git cat-file -e '${from_sha}^{commit}' 2>/dev/null \
      && git diff --stat '$from_sha' '$TARGET_SHA' -- '$2' | tail -1" 2>/dev/null || true
  fi
}
SRV_DIFF="$(diff_since "$RUN_SERVER_IMG" cloud/server)"
WEB_DIFF="$(diff_since "$RUN_WEB_IMG" cloud/web)"
echo "     cloud/server 差异: ${SRV_DIFF:-（无）}"
echo "     cloud/web    差异: ${WEB_DIFF:-（无）}"
if [ "$RUN_SERVER_IMG" = "podcloud-server:$IMAGE_TAG" ] && [ "$RUN_WEB_IMG" = "podcloud-web:$IMAGE_TAG" ]; then
  ok "两个 Deployment 都已经是 $IMAGE_TAG——无需发布（幂等空跑）"
  exit 0
fi

# ── 2. 备份数据库（WAL 模式下必须用 sqlite 的在线备份，不能直接 cp）──────────
step "2/6 备份数据库"
if [ "${NO_BACKUP:-0}" = "1" ]; then
  warn "NO_BACKUP=1 → 跳过备份"
elif [ "${DRY_RUN:-0}" = "1" ]; then
  echo "   [dry-run] 在 server Pod 内用 sqlite3 backup API 生成 podcloud.db.bak-$(date +%F)"
else
  # 直接 cp 会漏掉 -wal 里已提交的事务，备份是残缺的（库开了 WAL）。
  # sqlite 的 backup API 会生成一份包含 WAL 的一致快照。
  kubectl -n "$NS" exec deploy/podcloud-server -- python3 -c "
import sqlite3
src = sqlite3.connect('/app/data/podcloud.db')
dst = sqlite3.connect('/app/data/podcloud.db.bak-$(date +%F)')
src.backup(dst); dst.close(); src.close()
print('backup ok')
" || fail "数据库备份失败"
  ok "已备份: /app/data/podcloud.db.bak-$(date +%F)（sqlite 在线备份，含 WAL）"
fi

# ── 3. 在节点上构建镜像 ────────────────────────────────────────────────────
step "3/6 构建镜像（在 $NODE_NAME 上，tag=$IMAGE_TAG）"
if [ "${SKIP_BUILD:-0}" = "1" ]; then
  warn "SKIP_BUILD=1 → 假定镜像已在节点上"
elif [ "$LOCAL_BUILD" = "1" ]; then
  echo "   LOCAL_BUILD=1 → 在本机构建（$REPO_ROOT）"
  run_or_print bash -c "cd '$REPO_ROOT' && docker build --build-arg BUILD_TAG=$IMAGE_TAG \
    -f cloud/server/deploy/Dockerfile -t podcloud-server:$IMAGE_TAG cloud/server"
  run_or_print bash -c "cd '$REPO_ROOT' && docker build --build-arg BUILD_TAG=$IMAGE_TAG \
    -f cloud/web/deploy/Dockerfile -t podcloud-web:$IMAGE_TAG cloud/web"
  ok "镜像构建完成: podcloud-server:$IMAGE_TAG / podcloud-web:$IMAGE_TAG"
else
  # 构建前把工作树收敛到目标 commit：镜像必须对应一个可追溯的 commit，
  # 而不是"节点上那份不知道改了什么的源码"。
  run_or_print ssh_node "cd '$BUILD_DIR' && git checkout -f -q FETCH_HEAD"
  # BUILD_TAG 打进镜像：后端经 /api/v1/auth/config 的 build 字段暴露，
  # 前端打进产物显示在侧栏——于是"这个页面/这个实例是哪次构建"一眼可查，
  # 不用再靠"端点返回 401 还是 404"去猜版本。
  run_or_print ssh_node "cd '$BUILD_DIR' && docker build --build-arg BUILD_TAG=$IMAGE_TAG -f cloud/server/deploy/Dockerfile -t podcloud-server:$IMAGE_TAG cloud/server"
  run_or_print ssh_node "cd '$BUILD_DIR' && docker build --build-arg BUILD_TAG=$IMAGE_TAG -f cloud/web/deploy/Dockerfile -t podcloud-web:$IMAGE_TAG cloud/web"
  ok "镜像构建完成: podcloud-server:$IMAGE_TAG / podcloud-web:$IMAGE_TAG"
fi

# ── 4. 导入 k8s 的 containerd（docker 里的镜像 kubelet 看不见）──────────────
step "4/6 导入 containerd(k8s.io)"
if [ "$LOCAL_BUILD" = "1" ]; then
  # 本机构建的镜像要流式送进节点的 containerd（docker 的镜像 kubelet 看不见）
  for img in podcloud-server podcloud-web; do
    if [ "${DRY_RUN:-0}" = "1" ]; then
      echo "   [dry-run] docker save $img:$IMAGE_TAG | ssh ${SSH_USER}@${NODE_IP} ctr -n k8s.io images import -"
    else
      docker save "$img:$IMAGE_TAG" | ssh -o BatchMode=yes "${SSH_USER}@${NODE_IP}" \
        "ctr -n k8s.io images import - >/dev/null" || fail "$img 导入节点失败"
    fi
  done
else
  run_or_print ssh_node "docker save podcloud-server:$IMAGE_TAG | ctr -n k8s.io images import - >/dev/null"
  run_or_print ssh_node "docker save podcloud-web:$IMAGE_TAG    | ctr -n k8s.io images import - >/dev/null"
fi
if [ "${DRY_RUN:-0}" != "1" ]; then
  for img in podcloud-server podcloud-web; do
    ssh_node "ctr -n k8s.io images ls | grep -q '$img:$IMAGE_TAG'" \
      || fail "$img:$IMAGE_TAG 没进 containerd——kubelet 会拉不到镜像"
  done
  ok "两个镜像都已在 containerd 里（kubelet 可直接用）"
fi

# ── 5. 滚动发布：server 先滚完并就绪，再滚 web ──────────────────────────────
step "5/6 滚动发布（顺序：server → web）"
# 顺序是硬约束：新前端会调服务端新增端点，两个一起重启会出现
# 「新前端 + 旧后端」的窗口，用户刷新就 404（见 docs/rolling-update.md §4.2）。
if [ "${DRY_RUN:-0}" = "1" ]; then
  echo "   [dry-run] kubectl -n $NS set image deploy/podcloud-server server=podcloud-server:$IMAGE_TAG"
  echo "   [dry-run] kubectl -n $NS rollout status deploy/podcloud-server --timeout=300s"
  echo "   [dry-run] kubectl -n $NS set image deploy/podcloud-web web=podcloud-web:$IMAGE_TAG"
  echo "   [dry-run] kubectl -n $NS rollout status deploy/podcloud-web --timeout=300s"
else
  if [ "$RUN_SERVER_IMG" != "podcloud-server:$IMAGE_TAG" ]; then
    kubectl -n "$NS" set image deploy/podcloud-server "server=podcloud-server:$IMAGE_TAG" >/dev/null
    kubectl -n "$NS" rollout status deploy/podcloud-server --timeout=300s
    ok "server 已就绪: $IMAGE_TAG"
  else
    ok "server 已在 $IMAGE_TAG，跳过"
  fi
  if [ "$RUN_WEB_IMG" != "podcloud-web:$IMAGE_TAG" ]; then
    kubectl -n "$NS" set image deploy/podcloud-web "web=podcloud-web:$IMAGE_TAG" >/dev/null
    kubectl -n "$NS" rollout status deploy/podcloud-web --timeout=300s
    ok "web 已就绪: $IMAGE_TAG"
  else
    ok "web 已在 $IMAGE_TAG，跳过"
  fi
fi

# ── 6. 验证 ────────────────────────────────────────────────────────────────
step "6/6 验证"
if [ "${SKIP_VERIFY:-0}" = "1" ] || [ "${DRY_RUN:-0}" = "1" ]; then
  warn "跳过验证"
else
  kubectl -n "$NS" get pods -o custom-columns=\
NAME:.metadata.name,READY:.status.containerStatuses[*].ready,\
RESTARTS:.status.containerStatuses[*].restartCount,IMAGE:.spec.containers[*].image

  # 集群内自证：从 web Pod 里打自己的 nginx → 反代到 server。
  # 这是"应用真的在服务"的证据，且不依赖运行脚本这台机器能不能连上 NodePort。
  cfg="$(kubectl -n "$NS" exec deploy/podcloud-web -- \
    wget -qO- http://127.0.0.1/api/v1/auth/config 2>/dev/null || true)"
  if echo "$cfg" | grep -q is_private; then
    ok "集群内自证: web→server 反代正常"
  else
    fail "集群内自证失败：web Pod 打不到 server（$cfg）"
  fi
  # 直接核对构建标识，而不是靠"端点 401/404"猜版本：
  # 后端 /auth/config 的 build 字段就是本次 BUILD_TAG。
  deployed_build="$(printf '%s' "$cfg" | sed -n 's/.*"build":"\([^"]*\)".*/\1/p')"
  if [ "$deployed_build" = "$IMAGE_TAG" ]; then
    ok "后端构建标识 = $deployed_build（与本次发布一致）"
  else
    warn "后端构建标识为 '${deployed_build:-未知}'，本次发布 tag 是 $IMAGE_TAG（旧镜像没有该字段，属预期）"
  fi

  # NodePort 是**尽力而为**的检查：节点防火墙常只放行内网/反代机，
  # 跑脚本的机器未必能直连。连不上只 warn，不当成发布失败。
  NODE_PORT="$(kubectl -n "$NS" get svc podcloud-web-nodeport \
    -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || true)"
  if [ -n "$NODE_PORT" ]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "http://${NODE_IP}:${NODE_PORT}/" || true)"
    if [ "$code" = "200" ]; then
      ok "NodePort ${NODE_IP}:${NODE_PORT} 可达（200）"
    else
      warn "NodePort ${NODE_IP}:${NODE_PORT} 从这里不可达（$code）——若反代机不在同一网段属正常"
    fi
  fi

  if [ -n "${PUBLIC_URL:-}" ]; then
    pcode="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$PUBLIC_URL/" || true)"
    [ "$pcode" = "200" ] || fail "公开地址 $PUBLIC_URL 返回 $pcode"
    rules="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$PUBLIC_URL/api/v1/rules/pack" || true)"
    harden="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$PUBLIC_URL/api/v1/harden/reports" || true)"
    # 401 = 端点在、只是没带鉴权（正确）；404 = 还在跑旧版本
    [ "$rules" = "401" ] || warn "$PUBLIC_URL/api/v1/rules/pack 返回 $rules（期望 401）"
    [ "$harden" = "401" ] || warn "$PUBLIC_URL/api/v1/harden/reports 返回 $harden（期望 401）"
    ok "公开地址 $PUBLIC_URL: $pcode（rules=$rules harden=$harden）"
  fi
fi

echo
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  服务器集群发布完成${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo "  命名空间 : $NS"
echo "  目标版本 : ${TARGET_SHORT}（tag ${IMAGE_TAG}）"
echo "  回滚     : kubectl -n $NS rollout undo deploy/podcloud-web"
echo "             kubectl -n $NS rollout undo deploy/podcloud-server"
echo "             （顺序反过来：先退 web 再退 server，见 docs/rolling-update.md）"
echo "  构建缓存 : 节点 $BUILD_DIR（已 checkout 到 $TARGET_SHORT）"
