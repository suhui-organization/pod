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
    # 计费平台：stripe 已实现；paddle / creem / waffo 等 MoR 走同一套接口
    billing_provider: str = os.environ.get("PODCLOUD_BILLING_PROVIDER", "stripe")
    # Stripe 计费（provider=stripe 时使用）
    stripe_secret_key: str = os.environ.get("STRIPE_SECRET_KEY", "")
    stripe_webhook_secret: str = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    stripe_price_pro: str = os.environ.get("STRIPE_PRICE_PRO", "")  # 专业版订阅 price id
    stripe_price_free: str = os.environ.get("STRIPE_PRICE_FREE", "")
    # Paddle（provider=paddle 时使用；MoR，无海外主体也能收）
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
