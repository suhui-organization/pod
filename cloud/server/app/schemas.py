"""Pydantic 请求/响应模型。"""

from pydantic import BaseModel, Field

# 内网部署常使用 .local 等保留域;不采用 EmailStr(会拒绝特殊用途域名),
# 仅做最基础的格式校验,前端与服务端契约保持一致。
EMAIL_PATTERN = r"^[^\s@]+@[^\s@]+\.[^\s@]+$"


class RegisterRequest(BaseModel):
    email: str = Field(pattern=EMAIL_PATTERN)
    password: str
    full_name: str = ""
    tenant_name: str = ""
    client: str = "web"  # web | desktop


class LoginRequest(BaseModel):
    email: str = Field(pattern=EMAIL_PATTERN)
    password: str
    client: str = "web"  # web | desktop


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_in_minutes: int


class RefreshRequest(BaseModel):
    refresh_token: str


class TenantOut(BaseModel):
    id: int
    name: str
    slug: str
    plan: str

    model_config = {"from_attributes": True}


class UserOut(BaseModel):
    id: int
    email: str
    full_name: str

    model_config = {"from_attributes": True}


class UserCreateRequest(BaseModel):
    email: str = Field(pattern=EMAIL_PATTERN)
    password: str
    full_name: str = ""
    role: str = "member"  # admin | member


class UserUpdateRequest(BaseModel):
    full_name: str | None = None
    role: str | None = None
    is_active: bool | None = None
    password: str | None = None


class ProfileUpdateRequest(BaseModel):
    """本人改资料。只开放 full_name —— 邮箱是身份标识,改它要重新验证所有权。"""

    full_name: str = Field(default="", max_length=128)


class ChangePasswordRequest(BaseModel):
    """本人改密:必须带旧密码(管理员重置走 /admin/users/{id}/reset-password,不需要)。"""

    old_password: str
    new_password: str


class ForgotPasswordRequest(BaseModel):
    """申请重置链接。无论邮箱是否注册,响应都一样(防账号枚举)。"""

    email: str = Field(pattern=EMAIL_PATTERN)


class ResetPasswordRequest(BaseModel):
    """用邮件/日志里的一次性令牌换新密码。"""

    token: str
    new_password: str


class TenantSettingsOut(BaseModel):
    provider: str = "auto"
    api_key_set: bool = False   # 不回显密钥,只告知是否已配置
    model: str = ""
    base_url: str = ""          # OpenAI 兼容端点(provider=custom 时必填)
    mcp_commands: str = ""
    datasources: dict = {}      # 摘要(归一化后脱敏:databases[]/filesystems[] 仅 label/type/root,urls 域名,fircrawl 仅 configured)
    tool_policy: dict = {}      # 工具审批策略 {mode, rules[]}(P0)
    alert_webhook: dict = {}    # 告警通知 {enabled, channel, url, secret_set, min_severity}(url 含敏感,仅回显 secret_set)
    alert_smtp: dict = {}       # 邮件通知 {enabled, host, port, user_set, from_addr, to_addrs, tls}
    alert_rules: dict = {}      # 规则阈值 {deny_burst_threshold, burst_window_seconds, spike_threshold, silence_hours}
    ai_digest: dict = {}        # AI 日报 {enabled}（last_sent_date 不回显）


class TenantSettingsIn(BaseModel):
    # 模型三项一律 None = 不修改。默认值会覆盖已存配置(前端保存 webhook 时
    # 顺手把模型打回 auto/空模型,是历史 bug),这里不再给"看起来无害"的默认值。
    provider: str | None = None     # auto|deepseek|openai|custom|mock
    api_key: str | None = None      # None = 不修改已存密钥;空字符串 = 清除
    base_url: str | None = None     # None = 不修改
    model: str | None = None        # None = 不修改
    mcp_commands: str | None = None
    datasources: dict | None = None  # 完整数据源配置(含敏感字段,仅写入不回显)
    tool_policy: dict | None = None  # 工具审批策略 {mode: allow|ask|deny, rules: [{tool, mode}]}(None=不修改)
    alert_webhook: dict | None = None  # 告警通知配置(None=不修改)
    alert_smtp: dict | None = None     # 邮件通知配置(None=不修改)
    alert_rules: dict | None = None    # 规则阈值配置(None=不修改)
    ai_digest: dict | None = None      # AI 日报开关(None=不修改)


class LlmSettingsIn(BaseModel):
    """「AI 模型」面板的写入体：全部 None = 不修改。"""

    provider: str | None = None
    model: str | None = None
    base_url: str | None = None
    api_key: str | None = None      # None = 保留;空字符串 = 清除


class LlmTestIn(BaseModel):
    """测试连接：可先测未保存的配置，字段缺省时用已存配置。"""

    provider: str | None = None
    model: str | None = None
    base_url: str | None = None
    api_key: str | None = None


class SelfCheckIn(BaseModel):
    """一键自检：repair=true 时先自修复再检查。"""

    repair: bool = False
