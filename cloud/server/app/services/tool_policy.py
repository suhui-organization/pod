"""工具审批策略(Codex approval policy 移植):allow/ask/deny 规则档 + 会话审批缓存。

- 策略配置(租户 tenant_settings.tool_policy_json):
    {"mode": "allow|ask|deny", "rules": [{"tool": "query_*", "mode": "ask"}, ...]}
  规则按序匹配工具名(支持 fnmatch 通配符);未命中用默认 mode。
- ask 流程:创建 ToolApproval(pending) → 工具执行线程轮询 → 审批中心 decide
  (approved 放行执行 / rejected 返回拒绝原因给模型)。
- 缓存(Codex with_cached_approval):approved 决策按 (conversation, tool, args_hash)
  缓存,同会话同参数免审;拒绝不缓存(模型可调整参数重试)。
"""

import fnmatch
import hashlib
import json
import logging
import time as _time
from datetime import datetime

from app.models import ToolApproval, ToolApprovalCache

logger = logging.getLogger("podcloud.server")

ASK_POLL_INTERVAL = 2.0     # ask 轮询间隔(秒)
ASK_TIMEOUT = 600.0         # ask 等待上限(秒)


def args_hash(tool: str, args: dict) -> str:
    """审批缓存键:工具名 + 稳定序列化参数(键排序)的 sha256。"""
    payload = json.dumps({"tool": tool, "args": args or {}}, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_policy(policy_json: str) -> dict:
    try:
        p = json.loads(policy_json or "{}")
    except json.JSONDecodeError:
        p = {}
    if not isinstance(p, dict):
        p = {}
    mode = (p.get("mode") or "allow").strip().lower()
    if mode not in ("allow", "ask", "deny"):
        mode = "allow"
    rules = []
    for r in p.get("rules") or []:
        if not isinstance(r, dict):
            continue
        tool = str(r.get("tool") or "").strip()
        m = str(r.get("mode") or "").strip().lower()
        if tool and m in ("allow", "ask", "deny"):
            rules.append({"tool": tool, "mode": m})
    return {"mode": mode, "rules": rules}


def resolve_mode(policy: dict, tool: str) -> str:
    """按规则序匹配(通配符),未命中返回默认 mode。"""
    for r in policy.get("rules") or []:
        if fnmatch.fnmatch(tool, r["tool"]):
            return r["mode"]
    return policy.get("mode", "allow")


def cache_hit(db, tenant_id: int, conversation_id, tool: str, ahash: str) -> bool:
    """会话审批缓存:同 (会话, 工具, 参数) 已批准过 → 直接放行。"""
    if conversation_id is None:
        return False
    return (
        db.query(ToolApprovalCache.id)
        .filter(ToolApprovalCache.tenant_id == tenant_id,
                ToolApprovalCache.conversation_id == conversation_id,
                ToolApprovalCache.tool == tool,
                ToolApprovalCache.args_hash == ahash)
        .first()
        is not None
    )


def remember_approval(db, tenant_id: int, conversation_id, tool: str, ahash: str) -> None:
    """批准后写缓存(只记批准)。"""
    if conversation_id is None:
        return
    if cache_hit(db, tenant_id, conversation_id, tool, ahash):
        return
    db.add(ToolApprovalCache(tenant_id=tenant_id, conversation_id=conversation_id, tool=tool, args_hash=ahash))
    db.commit()


def create_approval(db, tenant_id: int, user_id: int, conversation_id, job_id, tool: str, args: dict) -> ToolApproval:
    row = ToolApproval(
        tenant_id=tenant_id, user_id=user_id,
        conversation_id=conversation_id, job_id=job_id,
        tool=tool, args_json=json.dumps(args or {}, ensure_ascii=False, default=str),
        args_hash=args_hash(tool, args),
    )
    db.add(row)
    db.commit()
    return row


def wait_for_decision(db, approval_id: int) -> str | None:
    """工具执行线程轮询审批结果,返回 None(批准)或拒绝原因文本;超时返回"审批超时"。

    每轮查询后结束事务(SQLite 读事务快照:不结束则看不到其他连接/线程的提交)。
    """
    deadline = _time.monotonic() + ASK_TIMEOUT
    while _time.monotonic() < deadline:
        row = db.query(ToolApproval).filter(ToolApproval.id == approval_id).first()
        db.commit()  # 结束读事务,下一轮可见外部提交
        if row is None:
            return "审批请求已不存在"
        if row.status == "approved":
            return None
        if row.status == "rejected":
            return row.reason or "已被拒绝"
        _time.sleep(ASK_POLL_INTERVAL)
    return f"审批超时(>{int(ASK_TIMEOUT)}s 未处理),已放弃执行"


def decide_approval(db, approval_id: int, decision: str, reason: str = "", decided_by: str = "") -> ToolApproval:
    """审批中心决定:approved 放行(写会话缓存)/ rejected 拒绝(不缓存)。"""
    row = db.query(ToolApproval).filter(ToolApproval.id == approval_id).first()
    if row is None:
        raise ValueError("审批不存在")
    if row.status != "pending":
        raise ValueError(f"审批已处理({row.status})")
    row.status = decision
    row.reason = reason[:2000]
    row.decided_by = decided_by[:128]
    row.decided_at = datetime.utcnow()
    db.commit()
    if decision == "approved":
        try:
            remember_approval(db, row.tenant_id, row.conversation_id, row.tool, row.args_hash)
        except Exception:  # noqa: BLE001 — 缓存失败不影响放行
            logger.warning("工具审批缓存写入失败", exc_info=True)
    return row


class PolicyGuardedTool:
    """策略守卫工具包装(Codex approval policy 移植):按租户策略 allow 直行 / ask 审批 / deny 拒绝。

    包装器保持原 Tool 接口(name/description/parameters/to_schema/execute);
    执行在 agent 线程内,使用独立 SessionLocal(不碰请求会话)。
    ask 流程:创建 ToolApproval → 轮询决策(上限 ASK_TIMEOUT) → 批准后执行 / 拒绝返回原因。
    会话缓存:同 (会话, 工具, 参数) 已批准 → 直接放行。
    """

    def __init__(self, tool, tenant_id: int, user_id: int, conversation_id=None, job_id=None, policy: dict | None = None):
        self._tool = tool
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.conversation_id = str(conversation_id) if conversation_id is not None else None
        self.job_id = job_id
        self.policy = policy or {"mode": "allow", "rules": []}

    # ── 透传原工具接口(工具协议不变) ──
    @property
    def name(self):
        return self._tool.name

    @property
    def description(self):
        return self._tool.description

    @property
    def parameters(self):
        return self._tool.parameters

    def to_schema(self):
        return self._tool.to_schema()

    def execute(self, **args):
        from app.database import SessionLocal

        mode = resolve_mode(self.policy, self._tool.name)
        if mode == "allow":
            return self._tool.execute(**args)
        if mode == "deny":
            return f"工具 {self._tool.name} 已被租户策略禁止(deny)"

        # ask:创建审批 → 轮询决策(独立 session,与请求线程隔离)
        s = SessionLocal()
        try:
            ahash = args_hash(self._tool.name, args)
            if cache_hit(s, self.tenant_id, self.conversation_id, self._tool.name, ahash):
                return self._tool.execute(**args)
            row = create_approval(s, self.tenant_id, self.user_id, self.conversation_id,
                                  self.job_id, self._tool.name, args)
            err = wait_for_decision(s, row.id)
            if err is None:
                return self._tool.execute(**args)
            return f"工具 {self._tool.name} 调用需人工审批,已放弃执行: {err}"
        finally:
            s.close()
