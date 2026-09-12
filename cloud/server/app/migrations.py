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
    "pod_subscriptions": {
        # 计费平台无关化：不再只存 stripe customer id
        "provider_customer_id": "ALTER TABLE pod_subscriptions ADD COLUMN provider_customer_id VARCHAR(64) DEFAULT ''",
        "provider_subscription_id": "ALTER TABLE pod_subscriptions ADD COLUMN provider_subscription_id VARCHAR(64) DEFAULT ''",
        "billing_provider": "ALTER TABLE pod_subscriptions ADD COLUMN billing_provider VARCHAR(16) DEFAULT ''",
    },
}


def migrate(engine) -> None:
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    for table, columns in _COLUMN_MIGRATIONS.items():
        if table not in tables:
            continue
        existing = {c["name"] for c in insp.get_columns(table)}
        for col, ddl in columns.items():
            if col in existing:
                continue
            logger.info("迁移: %s.%s 不存在,执行 %s", table, col, ddl)
            with engine.begin() as conn:
                conn.execute(text(ddl))
