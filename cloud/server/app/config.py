"""Pod Cloud 配置:环境变量优先,提供本地开发默认值。"""

import os
from dataclasses import dataclass


def _env_flag(name: str, *, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


_ENV = os.environ.get("PODCLOUD_ENV", "dev")


@dataclass
class Settings:
    db_url: str = os.environ.get(
        "PODCLOUD_DB_URL", "sqlite:///./podcloud.db"
    )
    jwt_secret: str = os.environ.get("PODCLOUD_JWT_SECRET", "dev-secret-change-me")
    jwt_expire_minutes: int = int(os.environ.get("PODCLOUD_JWT_EXPIRE_MINUTES", "720"))
    is_private: bool = os.environ.get("PODCLOUD_IS_PRIVATE", "false").lower() == "true"
    podcloud_env: str = _ENV
    provider: str = os.environ.get("PODCLOUD_PROVIDER", "auto")
    mcp_commands: str = os.environ.get("PODCLOUD_MCP_COMMANDS", "")
    # 免支付切换套餐：只在 dev 默认开启。
    # 关掉的理由是权限模型：require_admin 校验的是"租户管理员"，而每个注册
    # 用户都是自己租户的管理员 —— 不关就等于任何人一个 API 调用白拿 pro。
    allow_plan_switch: bool = _env_flag(
        "PODCLOUD_ALLOW_PLAN_SWITCH", default=(_ENV == "dev")
    )
    # 计费平台：paddle（MoR，唯一通道）；Creem / Waffo 等走同一套接口
    billing_provider: str = os.environ.get("PODCLOUD_BILLING_PROVIDER", "paddle")
    # 计费开关：auto（默认，有支付通道配置才启用）| on | off
    #   自托管/本地部署不需要收费能力——关掉之后：前端不显示订阅入口、
    #   结账与回调接口明确拒绝、agent 数量不再受套餐限制。
    #   auto 是为了兼容两种现实：配了 Paddle 的实例自动启用，没配的自然关闭。
    billing_enabled_setting: str = os.environ.get("PODCLOUD_BILLING_ENABLED", "auto").strip().lower()
    # ── 每日自检巡检 ──（详见 app/services/selfcheck_scheduler.py）
    selfcheck_enabled: str = os.environ.get("PODCLOUD_SELFCHECK_ENABLED", "on")
    selfcheck_hour: int = int(os.environ.get("PODCLOUD_SELFCHECK_HOUR", "8"))  # 北京时间整点
    selfcheck_repair: str = os.environ.get("PODCLOUD_SELFCHECK_REPAIR", "0")  # 1 = 先自修复
    selfcheck_notify: str = os.environ.get("PODCLOUD_SELFCHECK_NOTIFY", "fail")  # fail|all|off
    # 结构性迁移（要重建表的那种）前先按原样拷一份 SQLite 库文件；off 可关
    migrate_backup: str = os.environ.get("PODCLOUD_MIGRATE_BACKUP", "on")
    # Paddle（唯一计费通道：MoR，代收全球卡 / 代算代缴 VAT-GST，无海外主体也能收）
    paddle_api_key: str = os.environ.get("PADDLE_API_KEY", "")
    paddle_webhook_secret: str = os.environ.get("PADDLE_WEBHOOK_SECRET", "")
    paddle_price_pro: str = os.environ.get("PADDLE_PRICE_PRO", "")  # 专业版订阅价格 id（pri_…）
    # client-side token：给浏览器加载 Paddle.js 用。**本来就是公开值**（会出现在
    # 前端产物里），和 API key 不是一回事，别混用。
    paddle_client_token: str = os.environ.get("PADDLE_CLIENT_TOKEN", "")
    # sandbox | live。默认 sandbox —— 误配也只是打到测试环境，不会误扣真钱。
    paddle_env: str = os.environ.get("PADDLE_ENV", "sandbox")
    public_base_url: str = os.environ.get("PUBLIC_BASE_URL", "http://127.0.0.1:18087")
    # 找回密码的发信通道(系统级,部署时配)。留空 = 不发邮件,重置链接
    # 退化为写服务端日志。刻意不复用租户的 alert_smtp:单一管理员把自己
    # 锁在外面时进不去设置页,只能靠部署期配置救回自己。
    smtp_host: str = os.environ.get("PODCLOUD_SMTP_HOST", "")
    smtp_port: int = int(os.environ.get("PODCLOUD_SMTP_PORT", "465"))
    smtp_user: str = os.environ.get("PODCLOUD_SMTP_USER", "")
    smtp_password: str = os.environ.get("PODCLOUD_SMTP_PASSWORD", "")
    smtp_from: str = os.environ.get("PODCLOUD_SMTP_FROM", "")


settings = Settings()

# fail-fast:非开发环境或私有化实例必须显式配置强 JWT 密钥,否则拒绝启动。
if (settings.is_private or os.environ.get("PODCLOUD_ENV", "dev") != "dev") and (settings.jwt_secret == "dev-secret-change-me" or len(settings.jwt_secret) < 32):
    raise RuntimeError("生产/私有化部署必须设置 PODCLOUD_JWT_SECRET(至少 32 字节)")
