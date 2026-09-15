"""每日巡检 + 失败告警。

和 AI 日报同一套路子（后台线程 + 北京时间定时 + 按自然日去重），差别在：

- **每天都跑**，没配通知渠道也跑（结果落库，页面上能看到"最近巡检"）；
- **失败才告警**：自检里 warn 是"能更好"（比如没配 SMTP），fail 才是"坏了"。
  默认只对 fail 推通知，`PODCLOUD_SELFCHECK_NOTIFY=all` 才连 warn 一起推；
- 通知走租户在「设置 · 告警通知」里配好的 webhook / 邮件渠道，不另造一套。

环境变量：
  PODCLOUD_SELFCHECK_ENABLED   on（默认）/ off
  PODCLOUD_SELFCHECK_HOUR      巡检时刻，北京时间整点，默认 8
  PODCLOUD_SELFCHECK_REPAIR    1 = 巡检时先做安全自修复（默认 0，只报不改）
  PODCLOUD_SELFCHECK_NOTIFY    fail（默认）/ all / off
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.config import settings
from app.models import SelfCheckRun, Tenant, TenantSettings, TenantUser
from app.services import selfcheck as selfcheck_service
from app.services.alert_notify import email_async, load_webhook_cfg, notify_async
from app.services.audit import record_audit

logger = logging.getLogger("podcloud.selfcheck")

PUSH_TZ = timezone(timedelta(hours=8))  # 北京时间（与 AI 日报一致）
CHECK_INTERVAL = 60  # 秒


def enabled() -> bool:
    return (settings.selfcheck_enabled or "on").strip().lower() not in ("off", "false", "0", "no")


def _notify_mode() -> str:
    return (settings.selfcheck_notify or "fail").strip().lower()


def _repair_enabled() -> bool:
    return (settings.selfcheck_repair or "0").strip().lower() in ("1", "on", "true", "yes")


def _ran_today(db: Session, tenant_id: int, now: datetime) -> bool:
    """今天（北京时间自然日）已经巡检过就不重复跑 —— 重启不会重复推告警。"""
    day_start = now.astimezone(PUSH_TZ).replace(hour=0, minute=0, second=0, microsecond=0)
    since = day_start.astimezone(timezone.utc).replace(tzinfo=None)
    return (
        db.query(SelfCheckRun)
        .filter(
            SelfCheckRun.tenant_id == tenant_id,
            SelfCheckRun.trigger == "daily",
            SelfCheckRun.started_at >= since,
        )
        .first()
        is not None
    )


def _stamps(finished_at: datetime) -> tuple[str, str]:
    """返回 (机器可读的 UTC ISO, 给人看的北京时间)。

    存库/接口都是 naive UTC；通知里那句要写成本地时间并标明，
    否则收到"05:46 失败"的人对着 13:46 的钟会一脸问号。
    """
    finished_utc = finished_at.replace(tzinfo=timezone.utc)
    return finished_utc.isoformat(timespec="seconds"), finished_utc.astimezone(PUSH_TZ).strftime(
        "%Y-%m-%d %H:%M"
    )


def _alert_items(result: dict, mode: str) -> list[dict]:
    """把自检结果翻成告警渠道认得的形状（kind/severity/message/agent/ts）。"""
    wanted = ("fail",) if mode != "all" else ("fail", "warn")
    ts, _ = _stamps(result["finished_at"])
    items = [
        {
            "kind": "selfcheck",
            "severity": "high" if c["status"] == "fail" else "medium",
            "agent": "Pod Cloud",
            "message": f"{c['title']}：{c['detail']}",
            "ts": ts,
        }
        for c in result["checks"]
        if c["status"] in wanted
    ]
    return items


def run_daily_round(db: Session, now: datetime | None = None) -> list[int]:
    """给每个租户跑一次巡检；返回真正跑过的 tenant_id 列表（便于测试与日志）。"""
    now = now or datetime.now(PUSH_TZ)
    ran: list[int] = []
    # 遍历**租户**而不是租户设置：从没打开过「设置」页的租户也该被巡检到
    # （他们连 TenantSettings 行都还没有）。
    for tenant in db.query(Tenant).all():
        tenant_id = tenant.id
        try:
            if _ran_today(db, tenant_id, now):
                continue
            row = db.query(TenantSettings).filter(TenantSettings.tenant_id == tenant_id).first()
            result = selfcheck_service.run_checks(
                db,
                tenant_id=tenant_id,
                user_id=0,  # 定时巡检没有登录用户
                locale="zh-CN",
                repair_first=_repair_enabled(),
            )
            alerts = selfcheck_service.record_alerts(db, tenant_id, result)
            run = selfcheck_service.persist_run(db, tenant_id, "daily", result, alerts)
            admin = (
                db.query(TenantUser)
                .filter(TenantUser.tenant_id == tenant_id, TenantUser.role == "admin")
                .first()
            )
            if admin is not None:
                record_audit(
                    db,
                    tenant_id=tenant_id,
                    user_id=admin.user_id,
                    action="selfcheck.daily",
                    detail={
                        "summary": result["summary"],
                        "run_id": run.id,
                        "alerts_created": alerts["created"],
                        "alerts_auto_resolved": alerts["resolved"],
                    },
                )
            else:
                # 没有管理员可归属时就不写审计行（审计表的 user_id 是外键，
                # 塞 0 在 Postgres 上会直接违反约束）
                logger.warning("自检巡检无管理员可归属，跳过审计 tenant=%s", tenant_id)
            db.commit()
            ran.append(tenant_id)

            mode = _notify_mode()
            if mode == "off":
                continue
            items = _alert_items(result, mode)
            if not items:
                continue
            summary = result["summary"]
            ts, local = _stamps(result["finished_at"])
            items.insert(
                0,
                {
                    "kind": "selfcheck",
                    "severity": "high",
                    "agent": "Pod Cloud",
                    "message": (
                        f"每日自检：{summary['fail']} 项失败、{summary['warn']} 项警告"
                        f"（{local} 北京时间，共 {len(result['checks'])} 项）"
                    ),
                    "ts": ts,
                },
            )
            webhook_cfg = load_webhook_cfg(row.alert_webhook_json if row else "{}")
            if webhook_cfg.get("url"):
                notify_async(webhook_cfg, items)
            smtp_cfg = load_webhook_cfg(row.alert_smtp_json if row else "{}")
            if smtp_cfg.get("enabled"):
                email_async(smtp_cfg, items)
        except Exception as e:  # noqa: BLE001 单租户失败不影响其他租户
            logger.warning("selfcheck round tenant=%s failed: %s", tenant_id, e)
            db.rollback()
    return ran


def start_selfcheck_scheduler(get_db) -> threading.Thread:
    """后台线程：每 60s 看一眼是否到了巡检时刻（北京时间的 selfcheck_hour）。"""
    hour = max(0, min(23, settings.selfcheck_hour))

    def loop():
        last_date: str | None = None
        while True:
            try:
                now = datetime.now(PUSH_TZ)
                today = now.strftime("%Y-%m-%d")
                if now.hour == hour and now.minute < 5 and last_date != today:
                    db = next(get_db())
                    try:
                        ran = run_daily_round(db, now)
                        logger.info("selfcheck daily round: %s tenant(s)", len(ran))
                    finally:
                        db.close()
                    last_date = today
            except Exception as e:  # noqa: BLE001 巡检失败不影响服务
                logger.warning("selfcheck scheduler tick failed: %s", e)
            time.sleep(CHECK_INTERVAL)

    t = threading.Thread(target=loop, name="selfcheck", daemon=True)
    t.start()
    return t
