"""Pod Cloud：Agent 资产注册与管理（商业计划「资产与身份管理」模块）。

每个注册的 agent 对应一个本地 pod 网关实例；注册时生成一次性 sync token
（服务端只存 sha256 哈希），网关用它在 sync 端点推送审计。
"""

import json
from datetime import datetime
from hashlib import sha256
from secrets import token_urlsafe

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.i18n import EN, resolve_locale
from app.dependencies import require_admin
from app.models import Agent, AuditLog, SyncEvent
from app.security import get_current_tenant_id, get_current_user

router = APIRouter(prefix="/agents", tags=["agents"])


class AgentCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    # 留空则按名称自动推断（openclaw|claude-code|codex|hermes|cursor|dsh|other）
    platform: str = Field(default="", max_length=32)


def _infer_platform(name: str) -> str:
    n = name.lower()
    for kw, p in (
        ("openclaw", "openclaw"),
        ("claude", "claude-code"),
        ("codex", "codex"),
        ("hermes", "hermes"),
        ("cursor", "cursor"),
        ("dsh", "dsh"),
    ):
        if kw in n:
            return p
    return "other"


def agent_out(a: Agent, event_count: int = 0) -> dict:
    # 健康摘要由机器自己上报（只含计数），坏了就当没有——不用默认值冒充"健康"
    health = None
    if a.health_json:
        try:
            import json

            health = json.loads(a.health_json)
        except ValueError:
            health = None
    return {
        "id": a.id,
        "name": a.name,
        "platform": a.platform,
        "status": a.status,
        "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
        "event_count": event_count,
        # 熔断期望状态：web 下发，机器下次 pod sync 收敛到本地
        "quarantined": bool(a.quarantined),
        "quarantine_reason": a.quarantine_reason or "",
        "quarantined_at": a.quarantined_at.isoformat() if a.quarantined_at else None,
        "quarantined_by": a.quarantined_by or "",
        # 版本与健康（契约 docs/local-cloud-contract.md）：
        # "在线"不等于"真的在保护"，这三项让控制台能区分开
        "pod_version": a.pod_version or "",
        "protocol_version": int(a.protocol_version or 0),
        "health": health,
        "health_at": a.health_at.isoformat() if a.health_at else None,
        "created_at": a.created_at.isoformat(),
    }


@router.get("")
def list_agents(db: Session = Depends(get_db), tenant_id: int = Depends(get_current_tenant_id)):
    """当前租户的 agent 资产清单（含各自审计事件数）。"""
    agents = db.query(Agent).filter(Agent.tenant_id == tenant_id).order_by(Agent.id).all()
    counts = dict(
        db.query(SyncEvent.agent_id, func.count(SyncEvent.id))
        .filter(SyncEvent.tenant_id == tenant_id)
        .group_by(SyncEvent.agent_id)
        .all()
    )
    return {"agents": [agent_out(a, counts.get(a.id, 0)) for a in agents]}


@router.post("", status_code=201)
def register_agent(
    body: AgentCreateRequest,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    """注册 agent，返回一次性 sync token（仅此一次返回，服务端只存哈希）。"""
    require_admin(db, tenant_id, user)
    # 计划硬校验: 注册端强制 agent_limit(不只靠前端),超出返回 402
    # 计费关闭（本地/自托管）时不限量——否则自托管用户第 4 个 agent 就装不进来
    from app.models import Subscription
    from app.services.billing import billing_enabled

    sub = db.query(Subscription).filter(Subscription.tenant_id == tenant_id).first()
    if billing_enabled():
        limit = sub.agent_limit if sub else 3
        cnt = db.query(func.count(Agent.id)).filter(Agent.tenant_id == tenant_id).scalar() or 0
        if cnt >= limit:
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail=f"当前计划最多 {limit} 个 agent（已用 {cnt}）；升级计划后再注册",
            )
    sync_token = token_urlsafe(32)
    platform = body.platform or _infer_platform(body.name)
    agent = Agent(
        tenant_id=tenant_id,
        name=body.name,
        platform=platform,
        sync_token_hash=sha256(sync_token.encode("utf-8")).hexdigest(),
    )
    db.add(agent)
    db.flush()
    db.add(AuditLog(tenant_id=tenant_id, user_id=user["id"], action="agent.register", detail_json=f'{{"agent_id": {agent.id}}}'))
    db.commit()
    return {"agent": agent_out(agent), "sync_token": sync_token}


class QuarantineRequest(BaseModel):
    reason: str = Field(default="", max_length=500)


@router.post("/{agent_id}/quarantine")
def quarantine_agent(
    agent_id: int,
    body: QuarantineRequest,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    """下发熔断（期望状态）。

    这里**不直接改机器**——机器可能在 NAT 后面、可能离线。云端只记录"这台 agent 应该处于
    熔断状态"，机器下次 `pod sync` 时拉取并收敛到本地 quarantine.json，网关随即拒绝它的
    全部调用。幂等：重复下发不会产生额外效果，离线再久上线后也会收敛。
    """
    require_admin(db, tenant_id, user)
    agent = db.query(Agent).filter(Agent.id == agent_id, Agent.tenant_id == tenant_id).first()
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="agent 不存在")
    agent.quarantined = True
    agent.quarantine_reason = body.reason
    agent.quarantined_at = datetime.utcnow()
    # JWT 里没有 email，落库查一次——"谁下的熔断"是事后追责的关键字段，不能用 id 糊弄
    from app.models import User

    row = db.query(User).filter(User.id == user["id"]).first()
    agent.quarantined_by = row.email if row is not None else f"user:{user['id']}"
    db.add(
        AuditLog(
            tenant_id=tenant_id,
            user_id=user["id"],
            action="agent.quarantine",
            detail_json=json.dumps({"agent_id": agent.id, "reason": body.reason}),
        )
    )
    db.commit()
    return {"agent": agent_out(agent)}


@router.delete("/{agent_id}/quarantine")
def release_agent(
    agent_id: int,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    """解除熔断。

    机器侧只清理 `by=cloud` 的条目——**人工在机器上手工加的熔断不会被这里解除**
    （否则云端（或拿到 token 的人）就能悄悄解除人工的处置，那正是攻击者想要的）。
    """
    require_admin(db, tenant_id, user)
    agent = db.query(Agent).filter(Agent.id == agent_id, Agent.tenant_id == tenant_id).first()
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="agent 不存在")
    agent.quarantined = False
    agent.quarantine_reason = ""
    agent.quarantined_at = None
    agent.quarantined_by = ""
    db.add(
        AuditLog(
            tenant_id=tenant_id,
            user_id=user["id"],
            action="agent.release",
            detail_json=json.dumps({"agent_id": agent.id}),
        )
    )
    db.commit()
    return {"agent": agent_out(agent)}


@router.post("/{agent_id}/rotate-token")
def rotate_token(
    agent_id: int,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    """轮换 sync token（旧 token 立即失效）。"""
    require_admin(db, tenant_id, user)
    agent = db.query(Agent).filter(Agent.id == agent_id, Agent.tenant_id == tenant_id).first()
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="agent 不存在")
    sync_token = token_urlsafe(32)
    agent.sync_token_hash = sha256(sync_token.encode("utf-8")).hexdigest()
    db.add(AuditLog(tenant_id=tenant_id, user_id=user["id"], action="agent.rotate_token", detail_json=f'{{"agent_id": {agent.id}}}'))
    db.commit()
    return {"sync_token": sync_token}


@router.delete("/{agent_id}")
def remove_agent(
    agent_id: int,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    """删除 agent（级联删除其同步的审计事件）。"""
    require_admin(db, tenant_id, user)
    agent = db.query(Agent).filter(Agent.id == agent_id, Agent.tenant_id == tenant_id).first()
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="agent 不存在")
    db.query(SyncEvent).filter(SyncEvent.agent_id == agent_id, SyncEvent.tenant_id == tenant_id).delete()
    db.add(AuditLog(tenant_id=tenant_id, user_id=user["id"], action="agent.remove", detail_json=f'{{"agent_id": {agent.id}}}'))
    db.delete(agent)
    db.commit()
    return {"removed": agent_id}


# ---------------------------------------------------------------------------
# 一键接入脚本：GET /agent-setup/{agent_id}/{sync_token} 返回可粘贴执行的 bash
# （凭据即 sync_token，与 sync 端点同款校验；无需登录，可在任意机器执行）
# ---------------------------------------------------------------------------

setup_router = APIRouter(prefix="/agent-setup", tags=["agents"])


def _translate_script(script: str, locale: str) -> str:
    """把脚本里"用户会读到的输出"换成目标语言。

    只替换词表里有的整句（print/echo 的文案）；脚本注释保持中文——它们是
    实现说明，翻译的维护成本高于收益，也不影响使用。
    """
    if locale != "en-US":
        return script
    for zh, en in EN.items():
        if zh in script:
            script = script.replace(zh, en)
    return script


def _render_setup_script(
    name: str, agent_id: int, sync_token: str, api_url: str, locale: str = "zh-CN"
) -> str:
    """渲染接入脚本：写 cloud.json → 清失效绑定 → 同步 → 校验本 agent 真的上云。

    为什么要在脚本里清理旧绑定：pod sync 按 agents 数组逐个推送，遇到 401
    （token 已失效）会直接抛错中止，后面的绑定一个都不跑。老用户重装过控制台、
    或在页面上删过 agent，~/.pod/cloud.json 里就会残留死 token——结果是新接入的
    agent 永远显示"离线"，而页面和终端都不说原因。这里逐个 ping 把死绑定摘掉。
    """
    safe_name = name.replace("'", "'\\''")
    template = """#!/bin/bash
# Pod Cloud — agent 接入（__NAME__）
#
# 做三件事, 可重复执行(幂等):
#   1. 把该 agent 写进 ~/.pod/cloud.json
#   2. 清掉已经失效的旧绑定(死 token 会让 pod sync 整体中止)
#   3. 跑一次同步, 并单独校验本 agent 是否真的上云
set -e
API='__API_URL__'
AID=__AGENT_ID__
TOKEN='__SYNC_TOKEN__'
# 绑定到哪个本地 agent 的审计流。默认用控制台里填的名字，可用环境变量覆盖：
#   curl -fsSL <本命令> | LOCAL_AGENT=codex bash
LOCAL_AGENT="${LOCAL_AGENT:-__SAFE_NAME__}"
POD_DIR="$HOME/.pod"
CFG="$POD_DIR/cloud.json"
mkdir -p "$POD_DIR"
umask 077

# ── 定时同步 ──────────────────────────────────────────────────────────────
# 熔断下发与规则包是"机器主动拉"的（机器在 NAT 后面，服务端推不到它）。
# 没有定时任务，控制台上点的「熔断」永远到不了这台机器——通道是死的。
# 用 launchd / systemd --user / cron 装一个周期任务，各自调同一个包装脚本。
install_schedule() {
  if [ "${POD_NO_SCHEDULE:-0}" = "1" ]; then
    echo "   已跳过定时同步（POD_NO_SCHEDULE=1）。注意：不装的话，控制台上的熔断不会生效。"
    return 0
  fi
  POD_BIN="$(command -v pod 2>/dev/null || true)"
  if [ -z "$POD_BIN" ]; then
    echo "   ⚠️ 没找到 pod CLI，未安装定时同步；装好 pod 后重跑本命令即可。"
    return 0
  fi
  LOG="$POD_DIR/sync.log"
  WRAPPER="$POD_DIR/sync-job.sh"
  INTERVAL="${POD_SYNC_INTERVAL:-300}"

  # 包装脚本：日志轮转（超过 1MB 只留最后 200 行）+ 同步。
  # 每个调度器都只调它，规则不写三遍。
  cat > "$WRAPPER" <<'WRAPEOF'
#!/bin/bash
# 由 pod 接入脚本生成；删除本文件与下面的调度配置即可停用。
POD_DIR="$HOME/.pod"
LOG="$POD_DIR/sync.log"
if [ -f "$LOG" ] && [ "$(wc -c < "$LOG" 2>/dev/null || echo 0)" -gt 1000000 ]; then
  tail -200 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
fi
POD_BIN="__POD_BIN__"
exec "$POD_BIN" sync >> "$LOG" 2>&1
WRAPEOF
  # 绝对路径在调度器的最小 PATH 下也能找到（launchd/systemd 不继承交互式 PATH）
  python3 - "$WRAPPER" "$POD_BIN" <<'POD_SUBEOF'
import pathlib
import sys

p = pathlib.Path(sys.argv[1])
p.write_text(p.read_text().replace("__POD_BIN__", sys.argv[2]), encoding="utf-8")
POD_SUBEOF
  chmod +x "$WRAPPER"

  SCHED=""
  case "$(uname -s)" in
    Darwin)
      PLIST="$HOME/Library/LaunchAgents/dev.podsec.sync.plist"
      mkdir -p "$(dirname "$PLIST")"
      cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.podsec.sync</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$WRAPPER</string></array>
  <key>StartInterval</key><integer>$INTERVAL</integer>
  <key>RunAtLoad</key><false/>
</dict></plist>
PLISTEOF
      launchctl unload "$PLIST" >/dev/null 2>&1 || true
      launchctl load "$PLIST" >/dev/null 2>&1 && SCHED="launchd（每 ${INTERVAL}s）" || true
      ;;
    Linux)
      if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
        UD="$HOME/.config/systemd/user"
        mkdir -p "$UD"
        cat > "$UD/pod-sync.service" <<UNITEOF
[Unit]
Description=Pod Cloud sync (push audit, pull quarantine/rules)
[Service]
Type=oneshot
ExecStart=$WRAPPER
UNITEOF
        cat > "$UD/pod-sync.timer" <<TIMEREOF
[Unit]
Description=Periodic Pod Cloud sync

[Timer]
OnBootSec=2min
OnUnitActiveSec=${INTERVAL}s

[Install]
WantedBy=timers.target
TIMEREOF
        systemctl --user daemon-reload >/dev/null 2>&1 || true
        systemctl --user enable --now pod-sync.timer >/dev/null 2>&1 && SCHED="systemd --user（每 ${INTERVAL}s）" || true
        # 用户没登录时也要跑（否则笔记本合上盖子、没人登录就不同步了）
        loginctl enable-linger "$USER" >/dev/null 2>&1 || true
      fi
      if [ -z "$SCHED" ] && command -v crontab >/dev/null 2>&1; then
        MIN=$(( INTERVAL / 60 ))
        [ "$MIN" -lt 1 ] && MIN=1
        [ "$MIN" -gt 59 ] && MIN=59
        MARK="# pod-sync (installed by pod agent-setup)"
        ( crontab -l 2>/dev/null | grep -v -F "$MARK"; echo "*/$MIN * * * * $WRAPPER $MARK" ) | crontab - && SCHED="cron（每 ${MIN} 分钟）" || true
      fi
      ;;
  esac

  if [ -n "$SCHED" ]; then
    # 注意这里必须写 ${VAR}：bash 在 C.UTF-8 下会把紧跟 `$VAR` 的多字节字符
    # 的开头字节吃进变量名，结果是变量消失 + 这个汉字乱码。
    echo "   ⏱  已安装定时同步：${SCHED}——控制台上的熔断/规则包由此才能下发到这台机器。"
    echo "      日志：${LOG}　停用：删除 ${WRAPPER} 与对应的调度配置。"
  else
    echo "   ⚠️ 未能自动安装定时同步（没找到 launchd / systemd --user / cron）。"
    echo "      请自行把这条命令挂进定时任务，否则控制台上的熔断不会生效："
    echo "          $WRAPPER"
  fi
}

python3 - "$CFG" "$LOCAL_AGENT" "$AID" "$TOKEN" "$API" <<'POD_PYEOF'
import json
import os
import sys
import urllib.error
import urllib.request

cfg_path, name, aid, token, api_url = (
    sys.argv[1],
    sys.argv[2],
    int(sys.argv[3]),
    sys.argv[4],
    sys.argv[5],
)
api = api_url.rstrip("/")

# 本地审计按 ~/.pod/audit/<agent 名>/<server>.jsonl 存放, 同步时按 agent 名过滤。
# 名字对不上 = 一条都不会同步, 而 pod sync 只会说 "nothing to sync"——
# 用户看到的是"在线但审计事件永远是 0", 没有任何线索。这里提前对齐/说清楚。
audit_dir = os.path.join(os.path.dirname(cfg_path), "audit")
try:
    local_agents = sorted(
        d for d in os.listdir(audit_dir) if os.path.isdir(os.path.join(audit_dir, d))
    )
except OSError:
    local_agents = []

if local_agents and name not in local_agents:
    if len(local_agents) == 1:
        print("本地审计里只有「%s」，已自动把绑定名从「%s」对齐到它。" % (local_agents[0], name))
        name = local_agents[0]
    else:
        print("⚠️  绑定名「%s」在本机审计里找不到，这些事件不会被同步。" % name)
        print("   本机审计里现有的 agent：%s" % "、".join(local_agents))
        print("   解决：用对应的名字重跑一次这条命令，例如")
        print("        curl -fsSL <这条命令的地址> | LOCAL_AGENT=%s bash" % local_agents[0])
elif not local_agents:
    print("本地还没有审计数据（pod serve 跑起来之后才会有），先绑定名称「%s」。" % name)

try:
    with open(cfg_path, encoding="utf-8") as f:
        cfg = json.load(f)
    if not isinstance(cfg, dict):
        cfg = {}
except (OSError, ValueError):
    cfg = {}
cfg["api_url"] = api
# 按 agent_id 幂等去重（重复执行不产生重复条目）
agents = [a for a in cfg.get("agents", []) if not (isinstance(a, dict) and a.get("agent_id") == aid)]
agents.append({"local_agent": name, "agent_id": aid, "sync_token": token})


def still_accepted(binding):
    \"\"\"ping 一下：只有服务端明确回 401 才判定这个 token 已失效。
    网络不通/超时一律当作"不确定"，保留绑定，避免离线环境下误删配置。\"\"\"
    req = urllib.request.Request(
        api + "/api/v1/sync/ping",
        method="POST",
        headers={"X-Sync-Token": str(binding.get("sync_token", ""))},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
        return True
    except urllib.error.HTTPError as exc:
        return exc.code != 401
    except Exception:
        return True


kept, dropped = [], []
for binding in agents:
    if binding.get("agent_id") == aid:
        kept.append(binding)          # 刚写入的这条不需要验
    elif still_accepted(binding):
        kept.append(binding)
    else:
        dropped.append(binding)
cfg["agents"] = kept
with open(cfg_path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
print("已写入", cfg_path)
if dropped:
    ids = ", ".join("agent #%s" % d.get("agent_id") for d in dropped)
    print("已清理 %d 条失效绑定(%s)：它们的 token 已不被服务端承认。" % (len(dropped), ids))
    print("  这些是删过或换过库的 agent 残留；不清掉会让每次 pod sync 直接中止。")
POD_PYEOF

echo
if ! command -v pod >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
  echo "未检测到 pod CLI，尝试安装（npm 官方包 @podsec/cli）…"
  npm i -g @podsec/cli >/dev/null 2>&1 || echo "提示：自动安装失败（无 npm 或网络受限）"
fi

echo "同步本地审计…"
if command -v pod >/dev/null 2>&1; then
  SYNC_OUT="$(pod sync 2>&1)" && SYNC_RC=0 || SYNC_RC=$?
  printf '%s\\n' "$SYNC_OUT"
  if [ "$SYNC_RC" != "0" ]; then
    echo
    echo "⚠️  pod sync 没有全部成功。按原因处理："
    case "$SYNC_OUT" in
      *哈希链断裂*|*409*)
        echo "   · 哈希链断裂（409）：本地审计链自己就对不上（常见于同一 server 出现两条"
        echo "     相同 prev_hash 的事件）。云端拒绝上传无法证明连续性的数据——这是审计"
        echo "     可信度的底线,不能绕过。"
        echo "     处理:把出问题的那条链归档或删除后重跑,例如"
        echo "         mv ~/.pod/audit/<agent>/<server>.jsonl ~/.pod/audit/<agent>/<server>.jsonl.broken"
        ;;
      *401*)
        echo "   · 401：有绑定的令牌已失效。上面「清理失效绑定」那段应该已经摘掉它；"
        echo "     若本 agent 自己也报 401，回控制台重新生成接入命令再跑一次。"
        ;;
      *)
        echo "   · 其他错误:见上方 pod 的原始输出。"
        ;;
    esac
  fi
else
  echo "⚠️  未安装 pod CLI：配置已就绪，装好后执行 pod sync 即可。"
fi

# 结论只认服务端对**这个** agent 的答复, 不认 pod sync 的退出码。
# ping 的响应里带 agent_id:光"token 有效"不够, 还要确认它属于本命令要接入的
# 那个 agent —— 否则把 A 的 token 粘给 B, 谁都不会报错, 事件还会记到 A 头上。
echo
RESP="$(curl -s --max-time 10 -w '\\n%{http_code}' -X POST "$API/api/v1/sync/ping" -H "X-Sync-Token: $TOKEN" || printf '\\n000')"
CODE="${RESP##*$'\\n'}"
BODY="${RESP%$'\\n'*}"
GOT="$(printf '%s' "$BODY" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("agent_id",""))' 2>/dev/null || echo '')"
EVENTS="$(printf '%s' "$BODY" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("event_count",0))' 2>/dev/null || echo 0)"
case "$CODE" in
  200)
    if [ "$GOT" = "$AID" ]; then
      echo "✅ 已接入：agent #${AID}（__NAME__）在线，云端现有 ${EVENTS} 条审计。"
      if [ "$EVENTS" = "0" ]; then
        echo "   还没有审计上云：本地要先用 pod 网关跑出真实调用（pod serve / pod record），"
        echo "   之后 pod sync 会把它们推上来。控制台「Agent 资产」会自动显示在线。"
      else
        echo "   回到控制台「Agent 资产」/「时间线」，能看到这些审计。"
      fi
      install_schedule
    else
      echo "❌ 未接入：这个 sync token 属于 agent #${GOT}，不是本次要接入的 #${AID}。"
      echo "   解决：控制台 → Agent 资产 → agent #${AID} → 复制它的接入命令重跑一次。"
    fi
    ;;
  401)
    echo "❌ 未接入：服务端拒绝了这个 sync token（401）。"
    echo "   原因通常是：该 agent 在云端被删除过，或点过「重新生成接入命令」。"
    echo "   解决：控制台 → Agent 资产 → 该 agent → 重新生成接入命令，再跑一次。"
    ;;
  000)
    echo "❌ 未接入：连不上 ${API}"
    echo "   确认控制台服务在运行，且这台机器能访问该地址。"
    ;;
  *)
    echo "❌ 未接入：服务端返回 HTTP ${CODE}（配置已写好，稍后可重跑 pod sync）"
    ;;
esac
"""
    rendered = (
        template.replace("__NAME__", name)
        .replace("__SAFE_NAME__", safe_name)
        .replace("__AGENT_ID__", str(agent_id))
        .replace("__SYNC_TOKEN__", sync_token)
        .replace("__API_URL__", api_url)
    )
    return _translate_script(rendered, locale)


@setup_router.get("/{agent_id}/{sync_token}")
def agent_setup_script(
    agent_id: int,
    sync_token: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """返回该 agent 的一键接入脚本（凭据即 sync token，无需登录）。"""
    token_hash = sha256(sync_token.encode("utf-8")).hexdigest()
    agent = (
        db.query(Agent)
        .filter(Agent.id == agent_id, Agent.sync_token_hash == token_hash)
        .first()
    )
    if agent is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="sync token 无效")
    proto = request.headers.get("x-forwarded-proto", "http")
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or "127.0.0.1:8000"
    api_url = f"{proto}://{host}"
    locale = resolve_locale(request.headers.get("accept-language"), request.query_params.get("lang"))
    return Response(
        content=_render_setup_script(agent.name, agent.id, sync_token, api_url, locale),
        media_type="text/x-shellscript",
    )
