"""Pod Cloud：一键合规报告（商业计划「一键合规与审计」）。

GDPR Art.30 处理活动记录 + Art.32 安全措施说明，基于同步的审计事件生成。
报告为租户级只读聚合：不暴露参数原文（本地只同步了哈希），
并声明平台的安全措施（哈希链不可篡改 / 最小权限 / 审批闸门 / fail-closed）。
"""

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.models import Agent, Subscription, SyncEvent, Tenant
from app.security import get_current_tenant_id, get_current_user

router = APIRouter(prefix="/reports", tags=["reports"])


def _build_report(db: Session, tenant_id: int, days: int) -> dict:
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="租户不存在")
    since = datetime.utcnow() - timedelta(days=days)

    agents = db.query(Agent).filter(Agent.tenant_id == tenant_id).all()
    base = db.query(SyncEvent).filter(SyncEvent.tenant_id == tenant_id, SyncEvent.synced_at >= since)

    total_events = base.count()
    by_server = dict(base.with_entities(SyncEvent.server, func.count(SyncEvent.id)).group_by(SyncEvent.server).all())
    by_tool = (
        dict(base.with_entities(SyncEvent.tool, func.count(SyncEvent.id)).group_by(SyncEvent.tool).all())
        if total_events <= 200
        else {}
    )
    by_decision = dict(base.with_entities(SyncEvent.decision, func.count(SyncEvent.id)).group_by(SyncEvent.decision).all())
    approvals = (
        base.filter(SyncEvent.decision == "approve", SyncEvent.approver != "")
        .with_entities(SyncEvent.approver, SyncEvent.reason, func.count(SyncEvent.id))
        .group_by(SyncEvent.approver, SyncEvent.reason)
        .all()
    )

    timeline_rows = (
        db.query(SyncEvent)
        .filter(SyncEvent.tenant_id == tenant_id, SyncEvent.synced_at >= since)
        .order_by(SyncEvent.ts.desc())
        .limit(20)
        .all()
    )
    sub = db.query(Subscription).filter(Subscription.tenant_id == tenant_id).first()
    return {
        "tenant": {"id": tenant.id, "name": tenant.name, "slug": tenant.slug},
        "period": {"days": days, "since": since.isoformat(), "until": datetime.utcnow().isoformat()},
        "agents": [
            {
                "id": a.id,
                "name": a.name,
                "platform": a.platform,
                "status": a.status,
                "events": db.query(SyncEvent).filter(SyncEvent.agent_id == a.id, SyncEvent.synced_at >= since).count(),
            }
            for a in agents
        ],
        "activities": {
            "total_events": total_events,
            "by_server": by_server,
            "by_tool": by_tool,
            "by_decision": by_decision,
            "approvals": [{"approver": a, "reason": r or "", "count": c} for a, r, c in approvals],
        },
        "plan": sub.plan if sub else "free",
        "timeline": [
            {
                "ts": ev.ts,
                "agent": next((a.name for a in agents if a.id == ev.agent_id), str(ev.agent_id)),
                "server": ev.server,
                "tool": ev.tool,
                "decision": ev.decision,
                "outcome": ev.outcome,
                "approver": ev.approver or "",
                "policy_version": ev.policy_version,
            }
            for ev in timeline_rows
        ],
    }


def render_gdpr_markdown(report: dict) -> str:
    lines: list[str] = []
    t = report["tenant"]
    p = report["period"]
    a = report["activities"]
    lines.append(f"# GDPR 合规报告 — {t['name']}")
    lines.append("")
    lines.append(f"- 租户标识：`{t['slug']}`（id {t['id']}）")
    lines.append(f"- 报告期间：{p['since'][:19]}Z ~ {p['until'][:19]}Z（近 {p['days']} 天）")
    lines.append(f"- 订阅计划：{report['plan']}")
    lines.append("")

    lines.append("## 1. 处理活动记录（GDPR Art.30）")
    lines.append("")
    lines.append(f"报告期内共记录 **{a['total_events']}** 次 AI Agent 工具调用。")
    lines.append("")
    lines.append("### 1.1 按工具服务器聚合")
    lines.append("")
    lines.append("| 服务器 | 事件数 |")
    lines.append("|--------|--------|")
    for server, n in sorted(a["by_server"].items()):
        lines.append(f"| {server} | {n} |")
    if not a["by_server"]:
        lines.append("| （无事件） | 0 |")
    lines.append("")

    if a["by_tool"]:
        lines.append("### 1.2 按工具聚合")
        lines.append("")
        lines.append("| 工具 | 事件数 |")
        lines.append("|------|--------|")
        for tool, n in sorted(a["by_tool"].items(), key=lambda kv: -kv[1]):
            lines.append(f"| {tool} | {n} |")
        lines.append("")

    lines.append("### 1.3 决策分布")
    lines.append("")
    lines.append("| 决策 | 事件数 |")
    lines.append("|------|--------|")
    for d in ("allow", "approve", "deny"):
        lines.append(f"| {d} | {a['by_decision'].get(d, 0)} |")
    lines.append("")

    lines.append("### 1.4 人工审批记录")
    lines.append("")
    if a["approvals"]:
        lines.append("| 审批人 | 理由 | 次数 |")
        lines.append("|--------|------|------|")
        for ap in a["approvals"]:
            lines.append(f"| {ap['approver']} | {ap['reason'] or '—'} | {ap['count']} |")
    else:
        lines.append("报告期内无人工审批事件。")
    lines.append("")

    # 事件时间线（最近 20 条，作为 Art.30 的支撑证据）
    timeline_rows = report.get("timeline", [])
    if timeline_rows:
        lines.append("## 1.5 事件时间线（最近 20 条，证据链节选）")
        lines.append("")
        lines.append("| 时间 | Agent | 服务器 | 工具 | 决策 | 结果 | 审批人 | 策略版本 |")
        lines.append("|------|-------|--------|------|------|------|--------|----------|")
        for ev in reversed(timeline_rows):  # 旧→新
            lines.append(
                f"| {ev['ts'][:19]} | {ev['agent']} | {ev['server']} | "
                f"{ev['tool']} | {ev['decision']} | {ev['outcome']} | {ev['approver'] or '—'} | {ev['policy_version']} |"
            )
        lines.append("")
        lines.append("> 完整时间线可在平台「时间线」页回放；每条记录对应的参数/输出仅存 SHA-256 哈希。")
        lines.append("")

    lines.append("## 2. 处理活动主体（Agent 资产）")
    lines.append("")
    lines.append("| Agent | 平台 | 状态 | 事件数 |")
    lines.append("|-------|------|------|--------|")
    for ag in report["agents"]:
        lines.append(f"| {ag['name']} | {ag['platform']} | {ag['status']} | {ag['events']} |")
    if not report["agents"]:
        lines.append("| （未注册 Agent） | — | — | 0 |")
    lines.append("")

    lines.append("## 3. 技术安全措施（GDPR Art.32）")
    lines.append("")
    lines.append("- **不可篡改审计**：全部事件以 SHA-256 哈希链存储，任何篡改可被检测（本地与云端双重校验）。")
    lines.append("- **数据最小化**：事件仅同步参数哈希与元数据，不传输参数/输出原文。")
    lines.append("- **最小权限策略**：每个 Agent 按策略授权（deny > approve > allow），未授权工具默认拒绝（fail-closed）。")
    lines.append("- **人工审批闸门**：高危操作挂起等待人工批准，超时自动拒绝。")
    lines.append("- **密钥保护**：同步令牌仅存哈希，Agent 配置中的密钥暴露由 pod scan 持续监测。")
    lines.append("")
    lines.append("---")
    lines.append("本报告由 Pod Cloud 自动生成，数据来源于不可变审计链。")
    return "\n".join(lines)


@router.get("/gdpr")
def gdpr_report(
    days: int = 30,
    format: str = "json",  # json | markdown
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    """一键生成 GDPR 合规报告（json 或 markdown）。"""
    require_admin(db, tenant_id, user)
    days = min(max(days, 1), 365)
    report = _build_report(db, tenant_id, days)
    if format == "markdown":
        from fastapi.responses import PlainTextResponse

        return PlainTextResponse(
            render_gdpr_markdown(report),
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="gdpr-report-{tenant_id}.md"'},
        )
    return report
