"""Pod Cloud：agent 失联巡检（独立定时任务，不依赖 sync 触发）。

每轮检查所有租户下 last_seen_at 超过阈值的 agent，生成 agent_silence 告警
（24h 去重），并触发渠道通知（webhook / 邮件）。启动时立即跑一轮，
之后按 interval 循环（后台线程，单副本部署下有效）。
"""

import logging
import threading
import time
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.models import Agent, PodAlert, TenantSettings
from app.services.alert_notify import (
    _severity_ok,
    email_async,
    load_webhook_cfg,
    notify_async,
)

logger = logging.getLogger("podcloud.silence_watch")

SILENCE_HOURS = 24     # 失联阈值（小时）
DEDUP_HOURS = 24       # 告警去重窗口（小时）
INTERVAL_SECONDS = 1800  # 巡检间隔（30 分钟）


def _tenant_silence_hours(db: Session, tenant_id: int) -> int:
    """租户自定义失联阈值（回落默认）。"""
    import json

    row = db.query(TenantSettings).filter(TenantSettings.tenant_id == tenant_id).first()
    if row and row.alert_rules_json:
        try:
            rules = json.loads(row.alert_rules_json)
            if isinstance(rules, dict) and rules.get("silence_hours"):
                return max(1, min(720, int(rules["silence_hours"])))
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    return SILENCE_HOURS


def run_silence_check(db: Session) -> list[PodAlert]:
    """一轮巡检：返回新增的失联告警。"""
    now = datetime.utcnow()
    created: list[PodAlert] = []
    # 租户阈值缓存（同一租户多个 agent 只查一次）
    tenant_hours: dict[int, int] = {}
    for agent in db.query(Agent).filter(Agent.tenant_id.isnot(None)).all():
        if agent.tenant_id not in tenant_hours:
            tenant_hours[agent.tenant_id] = _tenant_silence_hours(db, agent.tenant_id)
        silence_hours = tenant_hours[agent.tenant_id]
        threshold = now - timedelta(hours=silence_hours)
        dedup_since = now - timedelta(hours=silence_hours)
        if agent.last_seen_at is None:
            continue  # 从未同步过的（含刚注册）不告警
        if agent.last_seen_at >= threshold:
            continue
        recent = (
            db.query(PodAlert)
            .filter(
                PodAlert.agent_id == agent.id,
                PodAlert.kind == "agent_silence",
                PodAlert.created_at >= dedup_since,
            )
            .first()
        )
        if recent is not None:
            continue
        alert = PodAlert(
            tenant_id=agent.tenant_id, agent_id=agent.id, kind="agent_silence",
            severity="medium",
            message=f"agent「{agent.name}」已超过 {silence_hours}h 未同步——可能离线或网关故障",
            event_seq=0, created_at=now,
        )
        db.add(alert)
        created.append(alert)
    db.commit()
    for alert in created:
        _notify_for_alert(db, alert)
    return created


def _notify_for_alert(db: Session, alert: PodAlert) -> None:
    row = db.query(TenantSettings).filter(TenantSettings.tenant_id == alert.tenant_id).first()
    if row is None:
        return
    agent = db.query(Agent).filter(Agent.id == alert.agent_id).first()
    agent_name = agent.name if agent else str(alert.agent_id)
    item = {
        "kind": alert.kind, "severity": alert.severity, "message": alert.message,
        "agent": agent_name, "ts": (alert.created_at or datetime.utcnow()).isoformat(),
    }
    wh = load_webhook_cfg(row.alert_webhook_json)
    if wh.get("enabled") and _severity_ok(wh.get("min_severity", "medium"), alert.severity):
        notify_async(wh, [item])
    try:
        import json

        smtp = json.loads(row.alert_smtp_json or "{}")
        if isinstance(smtp, dict) and smtp.get("enabled") and _severity_ok("medium", alert.severity):
            email_async(smtp, [item])
    except json.JSONDecodeError:
        pass


def start_silence_watch(get_db) -> threading.Thread:
    """启动后台巡检线程（daemon，随进程退出）。get_db: 会话工厂可调用对象。"""

    def loop():
        while True:
            try:
                db = next(get_db())
                try:
                    run_silence_check(db)
                finally:
                    db.close()
            except Exception as e:  # noqa: BLE001 巡检失败不影响进程
                logger.warning("silence watch round failed: %s", e)
            time.sleep(INTERVAL_SECONDS)

    t = threading.Thread(target=loop, name="silence-watch", daemon=True)
    t.start()
    return t
