"""自检逻辑（接口与每日巡检共用）。

为什么独立成 service：同一次自检有两条触发路径 —— 管理员在页面上点
「自检并修复」，以及后台的每日巡检。检查项必须一模一样，否则"我点了没问题、
巡检却说失败"。路由只负责鉴权/落库/返回，调度器只负责"到点跑 + 失败告警"。

检查项覆盖一串真实依赖：数据库能读能写、签名密钥不是默认值、租户还有人管、
agent 网关还在同步、审计链没断、模型真的连得上。每条都给真实数值或原始错误，
不写"系统正常"这种无法验证的话。

自修复只做安全、幂等、无副作用的那几件（补缺失的租户设置/订阅行、按心跳纠正
Agent 在线状态、清理悬空成员）——自修复不是"把检查结果改成通过"。
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from sqlalchemy import func, inspect, text
from sqlalchemy.orm import Session

from app.config import settings as cfg
from app.i18n import t
from app.models import (
    Agent,
    PodAlert,
    PodPolicy,
    PodPolicyVersion,
    SelfCheckRun,
    Subscription,
    SyncEvent,
    TenantSettings,
    TenantUser,
    User,
)
from app.services import billing as billing_service
from app.services import llm
from app.services.mailer import mailer_configured

# 心跳口径：15 分钟内同步过 = 网关活着；超过 24 小时 = 基本是停了
FRESH = timedelta(minutes=15)
STALE = timedelta(hours=24)

REQUIRED_TABLES = (
    "tenants",
    "users",
    "tenant_users",
    "tenant_settings",
    "pod_agents",
    "pod_sync_events",
    "pod_policies",
    "pod_policy_versions",
    "pod_alerts",
    "pod_subscriptions",
    "audit_logs",
)

# info = 这项不适用/没启用（例如自托管压根不打算用 AI）。它不是故障：
# 不计入 warn/fail、不进告警列表、不推通知，只在页面上如实说明。
PASS, WARN, FAIL, INFO = "pass", "warn", "fail", "info"
_RANK = {INFO: 0, PASS: 0, WARN: 1, FAIL: 2}


def _worst(statuses) -> str:
    return max(list(statuses) or [PASS], key=lambda s: _RANK[s])


def _check(
    cid: str,
    title: str,
    status: str,
    detail: str,
    hint: str = "",
    *,
    repairable: bool = False,
    repaired: bool = False,
) -> dict:
    return {
        "id": cid,
        "title": title,
        "status": status,
        "detail": detail,
        "hint": hint,
        "repairable": repairable,
        "repaired": repaired,
    }


def _ago(dt: datetime | None, locale: str) -> str:
    if dt is None:
        return t("从未同步", locale)
    days = (datetime.utcnow() - dt).days
    if days >= 1:
        return t("{n} 天前", locale, n=days)
    minutes = int((datetime.utcnow() - dt).total_seconds() // 60)
    if minutes >= 60:
        return t("{n} 小时前", locale, n=minutes // 60)
    return t("{n} 分钟前", locale, n=max(minutes, 0))


def repair(db: Session, tenant_id: int, locale: str) -> list[str]:
    """只做安全、幂等、无副作用的修复；返回"修了什么"的人话列表。"""
    done: list[str] = []

    if db.query(TenantSettings).filter(TenantSettings.tenant_id == tenant_id).first() is None:
        db.add(TenantSettings(tenant_id=tenant_id))
        done.append(t("租户设置行缺失，已补默认行", locale))

    if db.query(Subscription).filter(Subscription.tenant_id == tenant_id).first() is None:
        db.add(Subscription(tenant_id=tenant_id))
        done.append(t("订阅行缺失，已补免费计划行", locale))

    now = datetime.utcnow()
    for a in db.query(Agent).filter(Agent.tenant_id == tenant_id).all():
        expect = "online" if (a.last_seen_at and now - a.last_seen_at <= FRESH) else "offline"
        if a.status != expect:
            a.status = expect
            done.append(
                t(
                    "Agent「{name}」在线状态与心跳不一致，已纠正为「{status}」",
                    locale,
                    name=a.name,
                    status=t("在线", locale) if expect == "online" else t("离线", locale),
                )
            )

    for m in db.query(TenantUser).filter(TenantUser.tenant_id == tenant_id).all():
        if db.query(User).filter(User.id == m.user_id).first() is None:
            db.delete(m)
            done.append(t("清理了一条指向不存在用户的成员记录（user_id={uid}）", locale, uid=m.user_id))

    if done:
        db.commit()
    return done


def _check_database(db: Session, locale: str) -> dict:
    title = t("数据库连接与表结构", locale)
    try:
        db.execute(text("SELECT 1"))
        tables = set(inspect(db.get_bind()).get_table_names())
    except Exception as e:  # noqa: BLE001 —— 自检要如实回显原始错误
        return _check("database", title, FAIL, t("数据库不可用：{err}", locale, err=str(e)[:200]))
    missing = [x for x in REQUIRED_TABLES if x not in tables]
    if missing:
        return _check(
            "database",
            title,
            FAIL,
            t("连接正常，但缺表：{tables}", locale, tables=", ".join(missing)),
            t("重启服务会按迁移补齐缺失的表", locale),
        )
    return _check("database", title, PASS, t("连接正常，{n} 张表就绪", locale, n=len(tables)))


def _check_write(db: Session, locale: str) -> dict:
    title = t("数据库写入能力", locale)
    probe = "pod_selfcheck_probe"
    try:
        # 上一次检查没走完（比如另一项检查报错中断）时可能留下同名临时表 ——
        # 先清掉再建，否则会把"上次的残留"误报成"数据库写不进去"。
        db.execute(text(f"DROP TABLE IF EXISTS {probe}"))
        db.execute(text(f"CREATE TEMPORARY TABLE {probe} (id INTEGER)"))
        db.execute(text(f"INSERT INTO {probe} (id) VALUES (1)"))
        rows = db.execute(text(f"SELECT COUNT(*) FROM {probe}")).scalar()
        db.execute(text(f"DROP TABLE {probe}"))
        if rows != 1:
            raise RuntimeError(f"写入后读回 {rows} 行")
    except Exception as e:  # noqa: BLE001
        db.rollback()
        return _check(
            "write",
            title,
            FAIL,
            t("写不进去：{err}", locale, err=str(e)[:200]),
            t("检查磁盘是否写满、数据库账号是否有写权限", locale),
        )
    return _check("write", title, PASS, t("临时表建 / 写 / 读 / 删全部正常", locale))


def _check_secret(locale: str) -> dict:
    title = t("签名密钥强度", locale)
    weak = cfg.jwt_secret == "dev-secret-change-me" or len(cfg.jwt_secret) < 32
    if weak:
        return _check(
            "secret",
            title,
            FAIL,
            t("密钥长度 {n}，是默认值或过短", locale, n=len(cfg.jwt_secret)),
            t("生成 32 位以上随机串写进 PODCLOUD_JWT_SECRET 后重启（所有人需重新登录）", locale),
        )
    return _check("secret", title, PASS, t("密钥长度 {n}，非默认值", locale, n=len(cfg.jwt_secret)))


def _check_tenant(db: Session, tenant_id: int, user_id: int, locale: str) -> dict:
    title = t("租户与管理员", locale)
    rows = db.query(TenantUser).filter(TenantUser.tenant_id == tenant_id).all()
    admins = [r for r in rows if r.role == "admin"]
    orphans = [r for r in rows if db.query(User).filter(User.id == r.user_id).first() is None]
    me = next((r for r in rows if r.user_id == user_id), None)
    if me is None and user_id:
        return _check(
            "tenant",
            title,
            FAIL,
            t("当前账号不属于这个租户（成员 {n} 人）", locale, n=len(rows)),
            t("在成员管理里把自己加回来", locale),
        )
    if orphans:
        return _check(
            "tenant",
            title,
            WARN,
            t("{n} 条成员记录指向已删除的用户", locale, n=len(orphans)),
            t("点「自检并修复」会清理这些悬空记录", locale),
            repairable=True,
        )
    if not admins:
        return _check(
            "tenant",
            title,
            WARN,
            t("成员 {n} 人，但没有人是管理员", locale, n=len(rows)),
            t("需要人工把一名成员改成管理员（自动提权风险太大）", locale),
        )
    return _check(
        "tenant",
        title,
        PASS,
        t(
            "成员 {n} 人、管理员 {m} 人，当前角色 {role}",
            locale,
            n=len(rows),
            m=len(admins),
            role=me.role if me else t("定时巡检", locale),
        ),
    )


def _check_agents(db: Session, tenant_id: int, locale: str) -> dict:
    title = t("Agent 网关与心跳", locale)
    agents = db.query(Agent).filter(Agent.tenant_id == tenant_id).order_by(Agent.id).all()
    if not agents:
        return _check(
            "agents",
            title,
            WARN,
            t("还没有注册任何 Agent", locale),
            t("在「Agent 资产」里添加，然后在机器上跑一键接入命令", locale),
        )
    now = datetime.utcnow()
    events: dict[int, int] = {}
    for agent_id, cnt in (
        db.query(SyncEvent.agent_id, func.count(SyncEvent.id))
        .filter(SyncEvent.tenant_id == tenant_id)
        .group_by(SyncEvent.agent_id)
        .all()
    ):
        events[agent_id] = cnt
    lines: list[str] = []
    statuses: list[str] = []
    stale: list[str] = []
    for a in agents:
        if a.last_seen_at is None or now - a.last_seen_at > FRESH:
            statuses.append(WARN)
            stale.append(a.name)
        else:
            statuses.append(PASS)
        lines.append(
            t(
                "{name}：{ago}同步过（{events} 条事件，令牌{tok}）",
                locale,
                name=a.name,
                ago=_ago(a.last_seen_at, locale),
                events=events.get(a.id, 0),
                tok=t("已配", locale) if a.sync_token_hash else t("缺失", locale),
            )
        )
    hint = (
        t("在机器上跑一次 `pod sync` 看输出；网关没在跑时重跑接入脚本会把它拉起来", locale)
        if stale
        else ""
    )
    return _check("agents", title, _worst(statuses), " · ".join(lines), hint)


def _check_chain(db: Session, tenant_id: int, locale: str) -> dict:
    title = t("审计链完整性", locale)
    events = (
        db.query(SyncEvent)
        .filter(SyncEvent.tenant_id == tenant_id)
        .order_by(SyncEvent.agent_id, SyncEvent.server, SyncEvent.seq)
        .all()
    )
    if not events:
        return _check(
            "chain",
            title,
            WARN,
            t("还没有同步上来任何审计事件", locale),
            t("机器上先产生一次调用，再 `pod sync`", locale),
        )
    chains: dict[tuple[int, str], list[SyncEvent]] = {}
    for e in events:
        chains.setdefault((e.agent_id, e.server), []).append(e)
    for (agent_id, server), rows in chains.items():
        for i, ev in enumerate(rows):
            if not i:
                continue
            if ev.prev_hash != rows[i - 1].hash:
                return _check(
                    "chain",
                    title,
                    FAIL,
                    t(
                        "链断了：agent #{aid} / {server} 第 {seq} 条的 prev_hash 与上一条对不上",
                        locale,
                        aid=agent_id,
                        server=server,
                        seq=ev.seq,
                    ),
                    t("在本机跑 `pod verify-audit` 看原始链；不要删本地审计文件", locale),
                )
            if ev.seq != rows[i - 1].seq + 1:
                return _check(
                    "chain",
                    title,
                    FAIL,
                    t(
                        "序号不连续：agent #{aid} / {server} 从 {prev} 跳到 {seq}",
                        locale,
                        aid=agent_id,
                        server=server,
                        prev=rows[i - 1].seq,
                        seq=ev.seq,
                    ),
                )
    return _check(
        "chain",
        title,
        PASS,
        t("{chains} 条链、{n} 条事件哈希连续", locale, chains=len(chains), n=len(events)),
    )


def _check_policies(db: Session, tenant_id: int, locale: str) -> dict:
    title = t("策略就绪", locale)
    policies = db.query(PodPolicy).filter(PodPolicy.tenant_id == tenant_id).count()
    versions = db.query(PodPolicyVersion).filter(PodPolicyVersion.tenant_id == tenant_id).count()
    agents = db.query(Agent).filter(Agent.tenant_id == tenant_id).count()
    if policies == 0 and agents > 0:
        return _check(
            "policies",
            title,
            WARN,
            t("有 {n} 个 Agent，但还没有一条策略", locale, n=agents),
            t("到「策略中心」建一条基线策略并下发", locale),
        )
    return _check("policies", title, PASS, t("策略 {p} 条、版本 {v} 个", locale, p=policies, v=versions))


def _check_llm(db: Session, tenant_id: int, locale: str) -> dict:
    title = t("大模型可用性", locale)
    row = db.query(TenantSettings).filter(TenantSettings.tenant_id == tenant_id).first()
    try:
        model_cfg = llm.resolve_config(row)
    except llm.LlmConfigError as e:
        # 「没配」不是故障：自托管可以不启用任何 AI 功能（摘要/日报/策略草稿都是可选）。
        # 标成 info —— 不当警告、不进告警列表、不推通知，只告诉他要用来哪里配。
        # 「配了但调不通」才是 fail（见下），那是"说好要用却用不了"。
        return _check(
            "llm",
            title,
            INFO,
            t("未配置模型（可选的 AI 功能）：{err}", locale, err=str(e)[:160]),
            t(
                "要用 AI 摘要 / 日报 / 策略草稿，到「设置 · 模型」填 provider、模型与 API Key 并点连通性测试；"
                "不配也不影响自检、审计、策略、告警等其它功能",
                locale,
            ),
        )
    # 下面这一步要出网，最长 20 秒。**必须先收掉这一段读事务**：
    # SQLite 里"开着读事务再去写"的两个请求会互相锁死，而同步心跳是高频写。
    # 之前就是这里攥着读锁打电话，导致收尾 INSERT 直接 database is locked（线上 500）。
    db.commit()
    try:
        res = llm.test_connection(model_cfg)
    except Exception as e:  # noqa: BLE001 探测自己炸了也不能拖垮整轮自检
        return _check(
            "llm",
            title,
            FAIL,
            t("连通性探测异常：{err}", locale, err=str(e)[:200]),
            t("检查 API Key、base_url 与出网白名单", locale),
        )
    if not res.get("ok"):
        return _check(
            "llm",
            title,
            FAIL,
            t(
                "{provider}/{model} 调用失败：{err}",
                locale,
                provider=model_cfg.provider,
                model=model_cfg.model,
                err=(res.get("error") or "")[:200],
            ),
            t("检查 API Key、base_url 与出网白名单", locale),
        )
    return _check(
        "llm",
        title,
        PASS,
        t(
            "{provider}/{model} 可用（{ms} ms）",
            locale,
            provider=model_cfg.provider,
            model=model_cfg.model,
            ms=res.get("latency_ms"),
        ),
    )


def _check_mail(locale: str) -> dict:
    title = t("找回密码投递", locale)
    if mailer_configured():
        return _check("mail", title, PASS, t("已配置 SMTP，重置链接会发邮件", locale))
    return _check(
        "mail",
        title,
        WARN,
        t("未配置 SMTP：重置链接只写服务端日志", locale),
        t("自托管可以接受；要给用户发邮件就配 PODCLOUD_SMTP_*", locale),
    )


def _check_billing(locale: str) -> dict:
    title = t("计费开关", locale)
    if not billing_service.billing_enabled():
        return _check("billing", title, PASS, t("未启用计费（自托管默认），Agent 数量不受套餐限制", locale))
    if not cfg.billing_provider:
        return _check(
            "billing",
            title,
            FAIL,
            t("启用了计费但没写 PODCLOUD_BILLING_PROVIDER", locale),
            t("补上支付平台凭据，或把 PODCLOUD_BILLING_ENABLED 设成 off", locale),
        )
    return _check("billing", title, PASS, t("已启用计费，provider={p}", locale, p=cfg.billing_provider))


def run_checks(
    db: Session,
    *,
    tenant_id: int,
    user_id: int = 0,
    locale: str = "zh-CN",
    repair_first: bool = False,
) -> dict:
    """跑一遍全部检查。`repair_first=True` 时先做安全自修复，再检查。

    user_id=0 表示"没有登录用户"（定时巡检）：跳过"当前账号是否属于该租户"这条。

    每一项独立跑：**任何一项自己炸了（代码 bug、驱动异常）都只让那一项变红，
    其余照常检查完**。自检的全部价值就在"出了问题还能拿到其余结论"——
    如果因为某一项抛异常整轮 500，用户就什么都看不到（这条是线上踩过的坑）。
    """
    started = datetime.utcnow()
    repairs = repair(db, tenant_id, locale) if repair_first else []
    runners = [
        ("database", "数据库连接与表结构", lambda: _check_database(db, locale)),
        ("write", "数据库写入能力", lambda: _check_write(db, locale)),
        ("secret", "签名密钥强度", lambda: _check_secret(locale)),
        ("tenant", "租户与管理员", lambda: _check_tenant(db, tenant_id, user_id, locale)),
        ("agents", "Agent 网关与心跳", lambda: _check_agents(db, tenant_id, locale)),
        ("chain", "审计链完整性", lambda: _check_chain(db, tenant_id, locale)),
        ("policies", "策略就绪", lambda: _check_policies(db, tenant_id, locale)),
        ("llm", "大模型可用性", lambda: _check_llm(db, tenant_id, locale)),
        ("mail", "找回密码投递", lambda: _check_mail(locale)),
        ("billing", "计费开关", lambda: _check_billing(locale)),
    ]
    checks = []
    for cid, title, runner in runners:
        try:
            checks.append(runner())
        except Exception as e:  # noqa: BLE001 单项失败只影响单项
            db.rollback()  # 失败的查询可能把事务挂在坏状态上，先归位再继续
            checks.append(
                _check(
                    cid,
                    t(title, locale),
                    FAIL,
                    t("这一项检查自身出错：{err}", locale, err=str(e)[:200]),
                    t("这是自检自己的问题，请把这条报给维护者", locale),
                )
            )
    # 让"这次修了什么"落到对应条目上，而不是只给一句总结
    for c in checks:
        if c["id"] == "tenant":
            c["repaired"] = any("成员" in r for r in repairs)
        if c["id"] == "agents":
            c["repaired"] = any("在线状态" in r for r in repairs)
    finished = datetime.utcnow()
    summary = {
        "pass": sum(1 for c in checks if c["status"] == PASS),
        "warn": sum(1 for c in checks if c["status"] == WARN),
        "fail": sum(1 for c in checks if c["status"] == FAIL),
        "info": sum(1 for c in checks if c["status"] == INFO),
        "repaired": len(repairs),
    }
    return {
        "started_at": started,
        "finished_at": finished,
        "locale": locale,
        "summary": summary,
        "repairs": repairs,
        "checks": checks,
    }


def record_alerts(db: Session, tenant_id: int, result: dict) -> dict:
    """把 fail 的检查项写进告警列表（平台级：agent_id 为空，显示成 Pod Cloud）。

    为什么落告警而不只是发通知：通知是"推出去就没了"，告警列表才有
    未解决/已确认/已解决这套处置流程 —— 系统坏了要能派活、能追踪。

    口径是"**一个检查项同时最多一条活告警**"（按标题前缀认领，而不是比全文）：
    - 还在失败、已有活告警 → 只把文案更新成最新的错误（同一件事，别越堆越多）；
    - 还在失败、旧的那条已 resolved → 算复发，重新开一条（历史那条留着）；
    - 这次过了、还挂着没处理完的 → 自动标 resolved。问题已经自证消失，
      再让人手动关一遍是纯负担；只动 open / acknowledged（这两种都表示"没结论"），
      resolved 本来就完了。

    返回 {"created": [...id], "resolved": [...id]}，供审计留痕。
    """
    created: list[int] = []
    resolved: list[int] = []
    for c in result["checks"]:
        prefix = f"{c['title']}："
        latest = (
            db.query(PodAlert)
            .filter(
                PodAlert.tenant_id == tenant_id,
                PodAlert.kind == "selfcheck",
                PodAlert.message.like(f"{prefix}%"),
            )
            .order_by(PodAlert.id.desc())
            .first()
        )
        if c["status"] == FAIL:
            message = f"{prefix}{c['detail']}"
            if latest is not None and latest.state != "resolved":
                if latest.message != message:  # 错误原文变了（比如换了个报错）→ 就地更新
                    latest.message = message
                continue
            alert = PodAlert(
                tenant_id=tenant_id,
                agent_id=None,  # 平台级：不属于某个 agent
                kind="selfcheck",
                severity="high",
                message=message,
                event_seq=0,
                state="open",
                created_at=result["finished_at"],
            )
            db.add(alert)
            db.flush()  # 拿到 id，审计里能指到具体哪一条
            created.append(alert.id)
            continue
        if latest is not None and latest.state != "resolved":
            latest.state = "resolved"
            resolved.append(latest.id)
    db.flush()
    return {"created": created, "resolved": resolved}


def persist_run(
    db: Session, tenant_id: int, trigger: str, result: dict, alerts: dict | None = None
) -> SelfCheckRun:
    """把一次自检结果落库 —— 页面上的"最近巡检"与历史都读它。

    `alerts` 是 record_alerts() 的返回值：把"开了几条/自动关了几条"记进摘要，
    历史列表里就能看出这次巡检对告警列表做了什么。
    """
    summary = dict(result["summary"])
    if alerts:
        summary["alerts_created"] = len(alerts.get("created", []))
        summary["alerts_resolved"] = len(alerts.get("resolved", []))
    row = SelfCheckRun(
        tenant_id=tenant_id,
        trigger=trigger,
        started_at=result["started_at"],
        finished_at=result["finished_at"],
        summary_json=json.dumps(summary, ensure_ascii=False),
        checks_json=json.dumps(result["checks"], ensure_ascii=False),
        repairs_json=json.dumps(result["repairs"], ensure_ascii=False),
    )
    db.add(row)
    db.flush()
    return row


def serialize_run(row: SelfCheckRun) -> dict:
    return {
        "id": row.id,
        "trigger": row.trigger,
        "started_at": row.started_at.isoformat(timespec="seconds"),
        "finished_at": row.finished_at.isoformat(timespec="seconds"),
        "summary": json.loads(row.summary_json or "{}"),
        "repairs": json.loads(row.repairs_json or "[]"),
        "checks": json.loads(row.checks_json or "[]"),
    }
