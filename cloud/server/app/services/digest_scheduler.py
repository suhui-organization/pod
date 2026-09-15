"""Pod Cloud：AI 日报定时推送（每天 9:00 北京时间，复用 webhook/邮件渠道）。

- 只推送"已配置通知渠道（webhook 或 SMTP）且启用 AI 日报"的租户；
- 有告警 → 推送 AI 摘要；无告警 → 推送一句"昨日无告警"（系统存活证明）；
- 按自然日去重（TenantSettings.ai_digest_json.last_sent_date），重启不重复；
- 失败只记日志，不影响其他租户与主流程。
"""

import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import Agent, PodAlert, TenantSettings
from app.services.alert_notify import email_async, load_webhook_cfg, notify_async
from app.services import llm
from app.services.ai_summary import summarize

logger = logging.getLogger("podcloud.digest")

PUSH_TZ = timezone(timedelta(hours=8))  # 北京时间
PUSH_HOUR = 9
PUSH_MINUTE = 0
CHECK_INTERVAL = 60  # 秒


def _recent_alerts(db: Session, tenant_id: int, limit: int = 50) -> list[dict]:
    """近 24h 告警（新→旧），供摘要使用。原先这段在两个分支里各写了一遍。"""
    since = datetime.utcnow() - timedelta(hours=24)
    rows = (
        db.query(PodAlert, Agent.name)
        # 平台级告警（系统自检，agent_id 为空）也要进摘要：漏掉它，
        # 用户就会以为"昨天一切正常"，而其实是密钥/模型那类问题没被测到。
        .outerjoin(Agent, PodAlert.agent_id == Agent.id)
        .filter(PodAlert.tenant_id == tenant_id, PodAlert.created_at >= since)
        .order_by(PodAlert.id.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "agent": name or "Pod Cloud",
            "severity": a.severity,
            "kind": a.kind,
            "message": a.message,
            "ts": a.created_at.isoformat(),
        }
        for a, name in rows
    ]


def _audit_user_id(db: Session, tenant_id: int) -> int | None:
    """定时推送没有登录用户，模型调用留痕挂在租户管理员名下；查不到就跳过留痕。"""
    from app.models import TenantUser

    admin = (
        db.query(TenantUser)
        .filter(TenantUser.tenant_id == tenant_id, TenantUser.role == "admin")
        .first()
    )
    return admin.user_id if admin else None


def _digest_state(db: Session, tenant_id: int) -> dict:
    row = db.query(TenantSettings).filter(TenantSettings.tenant_id == tenant_id).first()
    if row is None:
        return {}, None
    try:
        state = json.loads(row.ai_digest_json or "{}")
        if not isinstance(state, dict):
            state = {}
    except json.JSONDecodeError:
        state = {}
    return state, row


def _has_channel(db: Session, row) -> bool:
    wh = load_webhook_cfg(row.alert_webhook_json)
    if wh.get("enabled") and wh.get("url"):
        return True
    try:
        smtp = json.loads(row.alert_smtp_json or "{}")
        if isinstance(smtp, dict) and smtp.get("enabled") and smtp.get("host") and smtp.get("to_addrs"):
            return True
    except json.JSONDecodeError:
        pass
    return False


def _push_digest(db: Session, row, summary: str, alerts_count: int, date_str: str) -> None:
    wh = load_webhook_cfg(row.alert_webhook_json)
    if wh.get("enabled") and wh.get("url"):
        notify_async(wh, [{
            "kind": "ai_digest", "severity": "low", "message": summary,
            "agent": "Pod Cloud", "ts": datetime.now(PUSH_TZ).isoformat(),
        }])
    try:
        smtp = json.loads(row.alert_smtp_json or "{}")
        if isinstance(smtp, dict) and smtp.get("enabled") and smtp.get("host") and smtp.get("to_addrs"):
            email_async(smtp, [{
                "kind": "ai_digest", "severity": "low", "message": summary,
                "agent": "Pod Cloud", "ts": datetime.now(PUSH_TZ).isoformat(),
            }])
    except json.JSONDecodeError:
        pass
    logger.info("digest pushed tenant=%s date=%s alerts=%d", row.tenant_id, date_str, alerts_count)


def push_digest_now(db: Session, tenant_id: int, user_id: int | None = None) -> dict:
    """手动立即推送一份 AI 日报（绕过每日去重，推送后更新 last_sent_date）。"""
    today = datetime.now(PUSH_TZ).strftime("%Y-%m-%d")
    state, row = _digest_state(db, tenant_id)
    if row is None:
        raise ValueError("租户设置不存在")
    try:
        cfg = llm.resolve_config(row)
    except llm.LlmConfigError as e:
        raise ValueError(str(e)) from e
    if not _has_channel(db, row):
        raise ValueError("未配置通知渠道：请先在设置页配置 webhook 或邮件")
    since = datetime.utcnow() - timedelta(hours=24)
    count = (
        db.query(PodAlert)
        .filter(PodAlert.tenant_id == tenant_id, PodAlert.created_at >= since)
        .count()
    )
    if count == 0:
        summary = f"✅ 昨日（{today}）无告警，一切正常。\n\n—— Pod Cloud 每日安全摘要"
    else:
        result = summarize(
            cfg,
            _recent_alerts(db, tenant_id),
            db=db,
            tenant_id=tenant_id,
            user_id=user_id or _audit_user_id(db, tenant_id),
            feature="alerts.digest",
        )
        summary = result["summary"]
    _push_digest(db, row, summary, count, today)
    state["last_sent_date"] = today
    row.ai_digest_json = json.dumps(state, ensure_ascii=False)
    db.commit()
    return {"pushed": True, "alerts_count": count, "date": today}


def run_digest_round(db: Session) -> list[int]:
    """一轮推送检查（可被测试直接调用）：返回成功推送的租户 id。"""
    pushed: list[int] = []
    today = datetime.now(PUSH_TZ).strftime("%Y-%m-%d")
    for row in db.query(TenantSettings).all():
        try:
            state, row2 = _digest_state(db, row.tenant_id)
            if not state.get("enabled"):
                continue
            if state.get("last_sent_date") == today:
                continue  # 今日已推（幂等）
            try:
                cfg = llm.resolve_config(row)
            except llm.LlmConfigError:
                continue  # 未配模型，跳过（配置后次日生效）
            if not _has_channel(db, row):
                continue  # 无通知渠道，跳过
            since = datetime.utcnow() - timedelta(hours=24)
            count = (
                db.query(PodAlert)
                .filter(PodAlert.tenant_id == row.tenant_id, PodAlert.created_at >= since)
                .count()
            )
            if count == 0:
                summary = f"✅ 昨日（{today}）无告警，一切正常。\n\n—— Pod Cloud 每日安全摘要"
            else:
                try:
                    result = summarize(
                        cfg,
                        _recent_alerts(db, row.tenant_id),
                        db=db,
                        tenant_id=row.tenant_id,
                        user_id=_audit_user_id(db, row.tenant_id),
                        feature="alerts.digest",
                    )
                    summary = result["summary"]
                except Exception as e:  # noqa: BLE001
                    logger.warning("digest summarize failed tenant=%s: %s", row.tenant_id, e)
                    continue
            _push_digest(db, row, summary, count, today)
            state["last_sent_date"] = today
            row.ai_digest_json = json.dumps(state, ensure_ascii=False)
            db.commit()
            pushed.append(row.tenant_id)
        except Exception as e:  # noqa: BLE001 单租户失败不影响其他
            logger.warning("digest round tenant=%s failed: %s", row.tenant_id, e)
            db.rollback()
    return pushed


def start_digest_scheduler(get_db) -> threading.Thread:
    """后台线程：每 60s 检查是否到达北京时间 9:00（跨天只推一次）。"""

    def loop():
        last_date: str | None = None
        while True:
            try:
                now = datetime.now(PUSH_TZ)
                today = now.strftime("%Y-%m-%d")
                at_hour = now.hour == PUSH_HOUR and 0 <= now.minute < 5
                if at_hour and last_date != today:
                    db = next(get_db())
                    try:
                        run_digest_round(db)
                    finally:
                        db.close()
                    last_date = today
            except Exception as e:  # noqa: BLE001
                logger.warning("digest scheduler tick failed: %s", e)
            time.sleep(CHECK_INTERVAL)

    t = threading.Thread(target=loop, name="ai-digest", daemon=True)
    t.start()
    return t
