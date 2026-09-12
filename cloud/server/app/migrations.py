"""轻量列迁移:为已有数据库补充新增列(幂等,启动时执行)。

MVP 阶段不使用 Alembic;生产升级时由部署流程保证先备份
(见 deploy/k8s/DEPLOY.md 升级章节)。
"""

import logging

from sqlalchemy import inspect, text

logger = logging.getLogger("finharness.server")

# 表 → 新增列 → DDL(幂等:列已存在则跳过)
_COLUMN_MIGRATIONS = {
    "users": {
        # 自助改密:记录改密时刻,用于让旧 token(iat 早于它)立即失效
        "password_changed_at": "ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMP NULL",
    },
    "tenant_settings": {
        "datasources_json": "ALTER TABLE tenant_settings ADD COLUMN datasources_json TEXT DEFAULT '{}'",
        "routing_json": "ALTER TABLE tenant_settings ADD COLUMN routing_json TEXT DEFAULT '{}'",
        # P1 记忆审批模式 + 预算
        "memory_approval": "ALTER TABLE tenant_settings ADD COLUMN memory_approval BOOLEAN DEFAULT FALSE",
        "memory_budget": "ALTER TABLE tenant_settings ADD COLUMN memory_budget INTEGER DEFAULT 20000",
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
    "task_deliveries": {
        "content_type": "ALTER TABLE task_deliveries ADD COLUMN content_type VARCHAR(128) DEFAULT ''",
    },
    "tasks": {
        "todos_json": "ALTER TABLE tasks ADD COLUMN todos_json TEXT DEFAULT '[]'",
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
    "plugins": {
        "hooks_json": "ALTER TABLE plugins ADD COLUMN hooks_json TEXT DEFAULT '{}'",
        # P0 宿主协议:插件包 id / manifest 快照 / 代码 / UI 槽位 / 启停 / 作用域 / 来源
        "plugin_id": "ALTER TABLE plugins ADD COLUMN plugin_id VARCHAR(64) DEFAULT ''",
        "manifest_json": "ALTER TABLE plugins ADD COLUMN manifest_json TEXT DEFAULT '{}'",
        "code_text": "ALTER TABLE plugins ADD COLUMN code_text TEXT DEFAULT ''",
        "ui_slots_json": "ALTER TABLE plugins ADD COLUMN ui_slots_json TEXT DEFAULT '[]'",
        "enabled": "ALTER TABLE plugins ADD COLUMN enabled BOOLEAN DEFAULT TRUE",
        "scope": "ALTER TABLE plugins ADD COLUMN scope VARCHAR(16) DEFAULT 'tenant'",
        "source": "ALTER TABLE plugins ADD COLUMN source VARCHAR(16) DEFAULT 'builtin'",
    },
    "usage_events": {
        "model": "ALTER TABLE usage_events ADD COLUMN model VARCHAR(64) DEFAULT ''",
    },
    "conversation_messages": {
        "name": "ALTER TABLE conversation_messages ADD COLUMN name VARCHAR(64) DEFAULT ''",
    },
    "outbound_campaigns": {
        "line_id": "ALTER TABLE outbound_campaigns ADD COLUMN line_id INTEGER NULL",
        # 插件式拨号通道:channel_id 引用 outbound_channels 实例
        "channel_id": "ALTER TABLE outbound_campaigns ADD COLUMN channel_id INTEGER NULL",
    },
    "mcp_servers": {
        "enabled": "ALTER TABLE mcp_servers ADD COLUMN enabled BOOLEAN DEFAULT TRUE",
        # P1:transport 类型 + url + headers/env(脱敏回显)
        "transport": "ALTER TABLE mcp_servers ADD COLUMN transport VARCHAR(16) DEFAULT 'stdio'",
        "url": "ALTER TABLE mcp_servers ADD COLUMN url VARCHAR(512) DEFAULT ''",
        "headers_json": "ALTER TABLE mcp_servers ADD COLUMN headers_json TEXT DEFAULT '{}'",
        "env_json": "ALTER TABLE mcp_servers ADD COLUMN env_json TEXT DEFAULT '{}'",
        "timeout_s": "ALTER TABLE mcp_servers ADD COLUMN timeout_s INTEGER DEFAULT 60",
    },
    "user_memories": {
        # B-6: 优先级 + 衰减字段
        "priority": "ALTER TABLE user_memories ADD COLUMN priority INTEGER DEFAULT 50",
        "access_count": "ALTER TABLE user_memories ADD COLUMN access_count INTEGER DEFAULT 0",
        "last_accessed_at": "ALTER TABLE user_memories ADD COLUMN last_accessed_at TIMESTAMP NULL",
        # P1 memento 双层: track/layer/pending
        "track": "ALTER TABLE user_memories ADD COLUMN track VARCHAR(16) DEFAULT 'user'",
        "layer": "ALTER TABLE user_memories ADD COLUMN layer VARCHAR(16) DEFAULT 'user'",
        "pending": "ALTER TABLE user_memories ADD COLUMN pending BOOLEAN DEFAULT FALSE",
    },
    "memory_feedback": {
        # B-7: 反馈表
        "tenant_id": "ALTER TABLE memory_feedback ADD COLUMN tenant_id INTEGER",
        "user_id": "ALTER TABLE memory_feedback ADD COLUMN user_id INTEGER",
        "feedback_type": "ALTER TABLE memory_feedback ADD COLUMN feedback_type VARCHAR(16)",
        "original_content": "ALTER TABLE memory_feedback ADD COLUMN original_content TEXT",
        "corrected_content": "ALTER TABLE memory_feedback ADD COLUMN corrected_content TEXT DEFAULT ''",
        "created_at": "ALTER TABLE memory_feedback ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
    },
}


# B-2 语义检索:pg_trgm 扩展 + GIN 索引 (幂等,首次启动自动建)
_TRGM_INDEX_MIGRATIONS = [
    # 启用 pg_trgm 扩展
    "CREATE EXTENSION IF NOT EXISTS pg_trgm",
    # conversation_messages.content 三元组 GIN 索引 (加速 % operator / similarity)
    "CREATE INDEX IF NOT EXISTS ix_conversation_messages_content_trgm "
    "ON conversation_messages USING gin (content gin_trgm_ops)",
    # user_memories.content 同样加速
    "CREATE INDEX IF NOT EXISTS ix_user_memories_content_trgm "
    "ON user_memories USING gin (content gin_trgm_ops)",
]


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

    # pg_trgm 扩展 + GIN 索引迁移 (PostgreSQL 专属;SQLite 自动跳过)
    if engine.dialect.name == "postgresql":
        for ddl in _TRGM_INDEX_MIGRATIONS:
            try:
                with engine.begin() as conn:
                    conn.execute(text(ddl))
                logger.info("迁移成功: %s", ddl[:80])
            except Exception as exc:  # noqa: BLE001
                logger.warning("pg_trgm 迁移跳过 (%s): %s", ddl[:60], exc)
