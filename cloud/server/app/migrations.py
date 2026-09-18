"""轻量列迁移：为已有数据库补充新增列（幂等，启动时执行）。

MVP 阶段不使用 Alembic；生产升级时由部署流程保证先备份。
注意：迁移项要与 app/models.py 里的表一一对应——模型删了却留着迁移项，
就是在给一张永远不存在的表写 DDL（历史包袱，已清理干净）。
"""

import logging

from sqlalchemy import inspect, text

logger = logging.getLogger("podcloud.server")

# 表 → 新增列 → DDL(幂等:列已存在则跳过)
_COLUMN_MIGRATIONS = {
    "users": {
        # 自助改密:记录改密时刻,用于让旧 token(iat 早于它)立即失效
        "password_changed_at": "ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMP NULL",
    },
    "tenant_settings": {
        # P0 工具审批策略(allow/ask/deny)
        "tool_policy_json": "ALTER TABLE tenant_settings ADD COLUMN tool_policy_json TEXT DEFAULT '{}'",
        # 告警通知 webhook 配置
        "alert_webhook_json": "ALTER TABLE tenant_settings ADD COLUMN alert_webhook_json TEXT DEFAULT '{}'",
        # 告警邮件通知配置
        "alert_smtp_json": "ALTER TABLE tenant_settings ADD COLUMN alert_smtp_json TEXT DEFAULT '{}'",
        # 告警规则阈值配置
        "alert_rules_json": "ALTER TABLE tenant_settings ADD COLUMN alert_rules_json TEXT DEFAULT '{}'",
        # AI 日报配置
        "ai_digest_json": "ALTER TABLE tenant_settings ADD COLUMN ai_digest_json TEXT DEFAULT '{}'",
        # AI 模型:OpenAI 兼容自建/中转端点(provider=custom 时必填)
        "base_url": "ALTER TABLE tenant_settings ADD COLUMN base_url VARCHAR(255) DEFAULT ''",
    },
    "pod_policies": {
        "note": "ALTER TABLE pod_policies ADD COLUMN note TEXT DEFAULT ''",
    },
    "pod_alerts": {
        "state": "ALTER TABLE pod_alerts ADD COLUMN state VARCHAR(16) DEFAULT 'open'",
    },
    "pod_agents": {
        # 云端下发熔断（期望状态）：机器 pod sync 时收敛到本地 quarantine.json
        "quarantined": "ALTER TABLE pod_agents ADD COLUMN quarantined BOOLEAN DEFAULT 0",
        "quarantine_reason": "ALTER TABLE pod_agents ADD COLUMN quarantine_reason TEXT DEFAULT ''",
        "quarantined_at": "ALTER TABLE pod_agents ADD COLUMN quarantined_at TIMESTAMP NULL",
        "quarantined_by": "ALTER TABLE pod_agents ADD COLUMN quarantined_by VARCHAR(128) DEFAULT ''",
        # 端 A 上报的版本与健康摘要（契约 docs/local-cloud-contract.md）
        "pod_version": "ALTER TABLE pod_agents ADD COLUMN pod_version VARCHAR(32) DEFAULT ''",
        "protocol_version": "ALTER TABLE pod_agents ADD COLUMN protocol_version INTEGER DEFAULT 0",
        "health_json": "ALTER TABLE pod_agents ADD COLUMN health_json TEXT DEFAULT ''",
        "health_at": "ALTER TABLE pod_agents ADD COLUMN health_at TIMESTAMP NULL",
        # 资产与发现的最近上报时间（新表由 create_all 建，这里只补 Agent 上的时间戳）
        "inventory_at": "ALTER TABLE pod_agents ADD COLUMN inventory_at TIMESTAMP NULL",
        "findings_at": "ALTER TABLE pod_agents ADD COLUMN findings_at TIMESTAMP NULL",
    },
    "pod_agent_assets": {
        # 新表由 create_all 建；这条是给"表已存在但缺列"的开发库兜底
        "harness": "ALTER TABLE pod_agent_assets ADD COLUMN harness VARCHAR(64) DEFAULT ''",
        # 资产是机器级快照：一条机器接多个绑定时会复制多份，Dashboard 按它去重
        "machine_id": "ALTER TABLE pod_agent_assets ADD COLUMN machine_id VARCHAR(32) DEFAULT ''",
    },
    "pod_agent_findings": {
        "machine_id": "ALTER TABLE pod_agent_findings ADD COLUMN machine_id VARCHAR(32) DEFAULT ''",
    },
    "pod_subscriptions": {
        # 计费平台无关化：不再只存单一平台的 customer id
        "provider_customer_id": "ALTER TABLE pod_subscriptions ADD COLUMN provider_customer_id VARCHAR(64) DEFAULT ''",
        "provider_subscription_id": "ALTER TABLE pod_subscriptions ADD COLUMN provider_subscription_id VARCHAR(64) DEFAULT ''",
        "billing_provider": "ALTER TABLE pod_subscriptions ADD COLUMN billing_provider VARCHAR(16) DEFAULT ''",
    },
}


def _column_exists(insp, table: str, col: str) -> bool:
    return col in {c["name"] for c in insp.get_columns(table)}


# 平台级告警（系统自检发现的云端问题）不挂在任何 agent 上，所以 pod_alerts.agent_id
# 必须允许为空。新库由 create_all 直接建对；老库这一列是 NOT NULL，得改。
_ALERT_COLUMNS = (
    "id",
    "tenant_id",
    "agent_id",
    "kind",
    "severity",
    "message",
    "event_seq",
    "state",
    "created_at",
)


def _needs_nullable_agent_id(insp, table: str) -> bool:
    if table not in set(insp.get_table_names()):
        return False
    col = next((c for c in insp.get_columns(table) if c["name"] == "agent_id"), None)
    return bool(col and not col.get("nullable", True))


def _make_agent_id_nullable(engine, table: str = "pod_alerts") -> None:
    """把 pod_alerts.agent_id 从 NOT NULL 改成可空。

    - Postgres：一条 ALTER 就够。
    - SQLite：改不了列的可空性，只能重建表（SQLite 官方的 12 步做法）。这里只做
      告警这一张小表，且显式列名复制、重建后把索引照原样补回来——不能丢索引，
      也不能因为列顺序变化把数据串位。

    重建前先按原样拷一份数据库文件（SQLite 才有），重建后**核对行数**；
    对不上就整笔回滚。这是唯一一处"动已有数据"的迁移，宁可多留一个备份文件。
    备份开关：PODCLOUD_MIGRATE_BACKUP=off 可关（默认开）。
    """
    dialect = engine.dialect.name
    if dialect != "sqlite":
        with engine.begin() as conn:
            conn.execute(text(f"ALTER TABLE {table} ALTER COLUMN agent_id DROP NOT NULL"))
        return

    backup = _backup_sqlite_file(engine)
    with engine.begin() as conn:
        ddl = conn.execute(
            text("SELECT sql FROM sqlite_master WHERE type='table' AND name=:t"), {"t": table}
        ).scalar()
        if not ddl or "agent_id INTEGER NOT NULL" not in ddl:
            return
        indexes = [
            r[0]
            for r in conn.execute(
                text("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name=:t AND sql IS NOT NULL"),
                {"t": table},
            ).all()
        ]
        new_ddl = ddl.replace(f"TABLE {table}", f"TABLE {table}_new", 1).replace(
            "agent_id INTEGER NOT NULL", "agent_id INTEGER", 1
        )
        cols = ", ".join(_ALERT_COLUMNS)
        before = _row_count(conn, table)
        conn.execute(text(new_ddl))
        conn.execute(text(f"INSERT INTO {table}_new ({cols}) SELECT {cols} FROM {table}"))
        after = _row_count(conn, f"{table}_new")
        if before != after:
            # 抛出去 → 整笔回滚（SQLite 的 DDL 也在事务里），旧表原样还在
            raise RuntimeError(
                f"迁移 {table} 行数对不上（{before} → {after}），已回滚"
                + (f"；迁移前备份：{backup}" if backup else "")
            )
        conn.execute(text(f"DROP TABLE {table}"))
        conn.execute(text(f"ALTER TABLE {table}_new RENAME TO {table}"))
        for idx in indexes:
            conn.execute(text(idx.replace(f"ON {table}", f"ON {table}", 1)))
    if backup:
        logger.warning("迁移: %s 已重建；迁移前备份留在 %s（确认无误后可删）", table, backup)


def _backup_sqlite_file(engine) -> str | None:
    """按原样拷一份 SQLite 库文件，返回备份路径（非 SQLite / 关掉开关 → None）。"""
    import os
    import shutil
    import time

    from app.config import settings

    if (getattr(settings, "migrate_backup", "on") or "").strip().lower() in ("off", "false", "0", "no"):
        return None
    url = engine.url
    if url.database in (None, "", ":memory:"):
        return None
    path = str(url.database)
    if not os.path.exists(path):
        return None
    dest = f"{path}.bak-{time.strftime('%Y%m%d-%H%M%S')}-pre-structural-migration"
    try:
        shutil.copy2(path, dest)
    except OSError as e:  # 备份失败就别动数据，让人先看日志
        raise RuntimeError(f"结构性迁移前备份失败，已中止：{e}") from e
    return dest


def _row_count(conn, table: str) -> int:
    """迁移前后对账用；单独抽出来是为了能被测试替换成"故意算错"的那种。"""
    return int(conn.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar() or 0)


def migrate(engine) -> None:
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    for table, columns in _COLUMN_MIGRATIONS.items():
        if table not in tables:
            continue
        for col, ddl in columns.items():
            if _column_exists(insp, table, col):
                continue
            logger.info("迁移: %s.%s 不存在,执行 %s", table, col, ddl)
            try:
                with engine.begin() as conn:
                    conn.execute(text(ddl))
            except Exception:
                # 滚动更新时新旧 Pod 会重叠：两个进程可能同时判定"列不存在"、
                # 各自执行 ALTER，后到的那个会报 duplicate column。
                # 重新查一次（用新的 inspector，避开缓存）：列已经在了就说明是
                # 并发同伴建的，算成功；否则才是真错误，照常抛出。
                if _column_exists(inspect(engine), table, col):
                    logger.info("迁移: %s.%s 已由并发实例创建，跳过", table, col)
                    continue
                raise

    # 结构性变更（可空性）单独走：SQLite 需要重建表，失败就抛，不静默半成品
    if _needs_nullable_agent_id(inspect(engine), "pod_alerts"):
        logger.info("迁移: pod_alerts.agent_id 改为可空（平台级告警不挂 agent）")
        _make_agent_id_nullable(engine)
