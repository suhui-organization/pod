"""数据模型:租户/用户/成员/用量/会话/审计/外呼。"""

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects import sqlite
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    slug: Mapped[str] = mapped_column(String(64), unique=True)
    plan: Mapped[str] = mapped_column(String(16), default="trial")
    is_private: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    full_name: Mapped[str] = mapped_column(String(128), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # 自助改密时间(UTC,微秒精度)。签发时间早于此值的 token 一律失效——
    # 这是"改密踢掉其他会话"的唯一依据,见 security.ensure_session_not_revoked。
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class TenantUser(Base):
    __tablename__ = "tenant_users"
    __table_args__ = (UniqueConstraint("tenant_id", "user_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    role: Mapped[str] = mapped_column(String(16), default="member")  # admin | member


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(64))
    detail_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class TenantSettings(Base):
    """租户级模型/Provider/MCP 设置(每个租户一行)。

    注意:api_key 为敏感信息,当前明文存储(私有化内网 MVP);
    生产环境建议改造为 KMS 加密(见 DEPLOY.md 密钥管理)。
    """

    __tablename__ = "tenant_settings"

    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), primary_key=True)
    provider: Mapped[str] = mapped_column(String(16), default="auto")  # auto|deepseek|openai|custom|mock
    api_key: Mapped[str] = mapped_column(String(255), default="")
    base_url: Mapped[str] = mapped_column(String(255), default="")  # provider=custom 时的 OpenAI 兼容端点
    model: Mapped[str] = mapped_column(String(64), default="")  # 空 = Provider 默认模型
    mcp_commands: Mapped[str] = mapped_column(Text, default="")  # 分号分隔的命令列表
    datasources_json: Mapped[str] = mapped_column(Text, default="{}")  # {database/filesystem/urls/firecrawl}(含敏感字段,明文 MVP)
    routing_json: Mapped[str] = mapped_column(Text, default="{}")  # P1 模型路由: {mode, routes[], fallback}
    memory_approval: Mapped[bool] = mapped_column(Boolean, default=False)  # P1 记忆审批模式:新写入进 pending
    memory_budget: Mapped[int] = mapped_column(Integer, default=20000)  # P1 记忆预算(字符,超限拒绝新写入)
    tool_policy_json: Mapped[str] = mapped_column(Text, default="{}")  # 工具审批策略 {mode: allow|ask|deny, rules: [{tool, mode}]}
    alert_webhook_json: Mapped[str] = mapped_column(Text, default="{}")  # 告警通知 {enabled, channel, url, secret, min_severity}
    alert_smtp_json: Mapped[str] = mapped_column(Text, default="{}")     # 邮件通知 {enabled, host, port, user, password, from_addr, to_addrs, tls}
    alert_rules_json: Mapped[str] = mapped_column(Text, default="{}")    # 告警规则阈值 {deny_burst_threshold, burst_window_seconds, spike_threshold, silence_hours}
    ai_digest_json: Mapped[str] = mapped_column(Text, default="{}")      # AI 日报 {enabled, last_sent_date}
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class UserPreference(Base):
    """用户偏好存储(JSON blob),支持跨设备同步 UI 状态等。

    单一 row per user,preferences_json 存任意 KV;后续可加 version 字段做乐观锁。
    """

    __tablename__ = "user_preferences"

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    preferences_json: Mapped[str] = mapped_column(Text, default="{}")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class PasswordResetToken(Base):
    """找回密码的一次性令牌。

    库里只存 sha256(明文):明文只在邮件/日志里出现一次,拿到库也换不回链接。
    单次使用(used_at)+ 短有效期,新申请会作废该用户所有未用令牌。
    """

    __tablename__ = "password_reset_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# ─────────────────────────────────────────────────────────────
# 抖音获客模块:热词 → 视频 → 评论 → AI 答案 → 审批 → 自动回写
# ─────────────────────────────────────────────────────────────


# ============ Pod Cloud（OPC AI Agent 安全舱 SaaS）============

class Agent(Base):
    """Pod Cloud：注册的本地网关/Agent 实例（租户下的资产清单）。"""

    __tablename__ = "pod_agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    name: Mapped[str] = mapped_column(String(64))
    platform: Mapped[str] = mapped_column(String(32), default="")  # openclaw|claude-code|cursor|dsh|other
    sync_token_hash: Mapped[str] = mapped_column(String(128), default="")  # sha256(sync token)，不存明文
    status: Mapped[str] = mapped_column(String(16), default="offline")  # online|offline
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    # 熔断（期望状态）：web 上下发，机器下次 pod sync 时收敛到本地 quarantine.json。
    # 存"期望状态"而不是"命令"：命令是一次性的，机器离线时错过就永远丢了；
    # 期望状态是幂等的，机器什么时候上线都会收敛过去。
    quarantined: Mapped[bool] = mapped_column(Boolean, default=False)
    quarantine_reason: Mapped[str] = mapped_column(Text, default="")
    quarantined_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    quarantined_by: Mapped[str] = mapped_column(String(128), default="")
    # 端 A 上报的版本与健康摘要（契约见 docs/local-cloud-contract.md）。
    # 为什么要有：控制台此前只知道"这台机器 30 分钟前在线"，但"在线"≠"真的在保护"——
    # 网关可能没起、审计链可能断了、还有 server 绕过网关。这三件事是"部署了但没生效"的
    # 典型形态，必须由机器自己上报（云端看不到本机文件）。
    # health_json 只存计数与时间戳，不含路径/主机名/配置原文。
    pod_version: Mapped[str] = mapped_column(String(32), default="")
    protocol_version: Mapped[int] = mapped_column(Integer, default=0)
    health_json: Mapped[str] = mapped_column(Text, default="")
    health_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    # 资产与发现的最近一次上报时间（用于显示"多久没上报"，与 health_at 分开记：
    # 三个通道各自可能失败，混在一起就说不清是哪一类数据旧了）
    inventory_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    findings_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class PodAgentAsset(Base):
    """机器上报的资产：一行一个 harness 或一个 MCP server。

    为什么单独建表而不是塞进 Agent 的 JSON 列：Dashboard 要按"哪些 server 绕过网关"
    跨机器聚合，SQL 能直接算，JSON 只能拉下来在 Python 里遍历。
    每次上报**整体替换**该 agent 的行（资产是快照，不是流水）。
    """

    __tablename__ = "pod_agent_assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("pod_agents.id"), index=True)
    # harness（本机装了哪个 agent 平台）| server（MCP server）
    kind: Mapped[str] = mapped_column(String(16))
    # harness id 或 server 名
    key: Mapped[str] = mapped_column(String(128))
    label: Mapped[str] = mapped_column(String(64), default="")
    installed: Mapped[bool] = mapped_column(Boolean, default=True)
    # harness：是否被 pod 纳管（有策略/审计/身份）；server：是否经过网关（用 behind_gateway）
    managed: Mapped[bool] = mapped_column(Boolean, default=False)
    managed_by_json: Mapped[str] = mapped_column(Text, default="[]")
    behind_gateway: Mapped[bool] = mapped_column(Boolean, default=False)
    record_only: Mapped[bool] = mapped_column(Boolean, default=False)
    scope: Mapped[str] = mapped_column(String(16), default="")
    package: Mapped[str] = mapped_column(String(128), default="")
    pinned: Mapped[bool] = mapped_column(Boolean, default=False)
    # server 归哪个 harness 管（harness 行本身为空）；控制台要显示"这些 server 属于谁"
    harness: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class PodAgentFinding(Base):
    """机器上报的发现：一行一条聚合（威胁/类别 × 级别 × harness）。

    只存"哪个威胁、多严重、落在哪、几处"——证据与路径留在本机报告里。
    """

    __tablename__ = "pod_agent_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("pod_agents.id"), index=True)
    # guard=漏洞扫描（key 是 AG-xx）；posture=控制平面姿态（key 是类别）
    source: Mapped[str] = mapped_column(String(16))
    key: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    harness: Mapped[str] = mapped_column(String(64), default="")
    count: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class SyncEvent(Base):
    """Pod Cloud：本地网关同步上来的审计事件（与 pod 本地哈希链同构，敏感内容只存哈希）。"""

    __tablename__ = "pod_sync_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    # NULL = 平台级告警（系统自检发现的云端问题，不挂在某个 agent 上）。
    # 老库该列是 NOT NULL，启动时的迁移会把它改掉（见 migrations.py）。
    agent_id: Mapped[int] = mapped_column(ForeignKey("pod_agents.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    ts: Mapped[str] = mapped_column(String(64))
    server: Mapped[str] = mapped_column(String(64))
    tool: Mapped[str] = mapped_column(String(128))
    args_hash: Mapped[str] = mapped_column(String(64))
    decision: Mapped[str] = mapped_column(String(16))
    outcome: Mapped[str] = mapped_column(String(16), default="")
    approver: Mapped[str] = mapped_column(String(64), default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    policy_version: Mapped[str] = mapped_column(String(32), default="")
    enforced: Mapped[bool] = mapped_column(Boolean, default=True)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64))
    synced_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# 控制平面事件的链标识（与 pod 本地审计文件名 <audit>/<agent>/control.jsonl 对齐）。
# 服务端用它做链连续性校验：不能用事件类别当键，否则同一文件里不同类别会互相判成断链。
CONTROL_CHAIN = "control"


class PodControlEvent(Base):
    """Pod Cloud：控制平面事件（钩子/配置冻结/记忆/包来源/身份/委托/令牌/熔断/异常）。

    与 SyncEvent 分开建表的原因：数据平面事件回答"agent 做了什么"（工具调用），
    控制平面事件回答"谁改了 agent 的运行环境"（钩子被改写、配置降级、身份缺失、
    委托越权……）。两者的维度、保留策略与展示方式都不同，混在一张表里会互相污染
    查询与索引。

    与本地哈希链同构：同一 agent 的同一链（pod 侧写入 <audit>/<agent>/control.jsonl）
    在云端继续用 prev_hash/hash 串起来，敏感内容只存哈希。
    """

    __tablename__ = "pod_control_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("pod_agents.id"), index=True)
    # 链标识：pod 侧控制平面事件统一用 'control'（与审计文件名一致），
    # 服务端据此做链连续性校验——不能用事件自身的类别当键。
    chain: Mapped[str] = mapped_column(String(64), default=CONTROL_CHAIN)
    kind: Mapped[str] = mapped_column(String(32))  # hook|config-change|memory|package|identity|delegation|grant|quarantine|anomaly|metadata
    category: Mapped[str] = mapped_column(String(32), default="")  # pod 侧 tool 字段：hook|config|memory|...
    seq: Mapped[int] = mapped_column(Integer)
    ts: Mapped[str] = mapped_column(String(64))
    decision: Mapped[str] = mapped_column(String(16), default="allow")
    outcome: Mapped[str] = mapped_column(String(16), default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    args_hash: Mapped[str] = mapped_column(String(64), default="")
    policy_version: Mapped[str] = mapped_column(String(32), default="")
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64))
    synced_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class PodPolicy(Base):
    """Pod Cloud：云端策略（模板库/按 agent 下发）。agent_id 为空 = 租户模板。"""

    __tablename__ = "pod_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("pod_agents.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(64))
    policy_json: Mapped[str] = mapped_column(Text, default="{}")
    note: Mapped[str] = mapped_column(Text, default="")  # 设计说明/备注（记录"为什么这么设"）
    version: Mapped[str] = mapped_column(String(32), default="0.1.0")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class PodPolicyVersion(Base):
    """Pod Cloud：策略版本历史（每次保存/模板覆盖存一份快照，支持 diff 与回滚）。"""

    __tablename__ = "pod_policy_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("pod_policies.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    policy_json: Mapped[str] = mapped_column(Text, default="{}")
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class PodRulePack(Base):
    """Pod Cloud：规则包（订阅式加固的分发单元，对应本地 `pod rules`）。

    本地 `pod rules pull` 拉取后由**客户端**验签 + 过放宽守卫才生效。
    云端刻意不做任何判定：
    - 不验签——公钥在客户端手里，云端验了也不构成信任（它能同时换掉包和公钥）；
    - 不判断是否放宽——那是客户端守卫的职责（packages/policy/src/rules-pack.ts）。
    云端只做三件事：存、标 active、记审计。

    每租户同时只有一个 active：撤回 = 激活上一版，而不是删除——保留"曾经下发过什么"的证据。
    """

    __tablename__ = "pod_rule_packs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    pack_version: Mapped[str] = mapped_column(String(64))
    issued_by: Mapped[str] = mapped_column(String(64))
    note: Mapped[str] = mapped_column(Text, default="")
    # 含 signature 的整包原文：客户端拿去自己验签，云端不解析内部语义
    pack_json: Mapped[str] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class PodHardenReport(Base):
    """Pod Cloud：加固审计报告（`pod harden` 的交付物）。

    只收**交付物**（report.md + findings.json），不收 evidence.json（原始审计链）。
    后者是"本地优先"承诺的核心，客户没打算把它交出去。

    上传是显式动作（`pod harden --upload`）：报告里含路径与工具名等业务信息，
    不能因为"配了云"就默认传上去。
    """

    __tablename__ = "pod_harden_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("pod_agents.id"), index=True)
    generated_at: Mapped[str] = mapped_column(String(64))
    high: Mapped[int] = mapped_column(Integer, default=0)
    medium: Mapped[int] = mapped_column(Integer, default=0)
    low: Mapped[int] = mapped_column(Integer, default=0)
    mcp_servers: Mapped[int] = mapped_column(Integer, default=0)
    exposed_secrets: Mapped[int] = mapped_column(Integer, default=0)
    broken_chains: Mapped[int] = mapped_column(Integer, default=0)
    rules_version: Mapped[str] = mapped_column(String(64), default="")
    # 报告正文（markdown）与机器可读发现；两者都是已脱敏的交付物
    report_md: Mapped[str] = mapped_column(Text, default="")
    findings_json: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class SelfCheckRun(Base):
    """一次系统自检的结果（手动或每日巡检）。

    为什么要落库：页面上的「最近巡检」与巡检历史都读它；每日巡检也靠它做
    "今天已经跑过了"的幂等判断（重启不会重复推告警）。
    """

    __tablename__ = "pod_selfcheck_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    trigger: Mapped[str] = mapped_column(String(16), default="manual")  # manual | daily
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    finished_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    summary_json: Mapped[str] = mapped_column(Text, default="{}")   # {pass,warn,fail,repaired}
    checks_json: Mapped[str] = mapped_column(Text, default="[]")    # 逐项结果（含详情/建议）
    repairs_json: Mapped[str] = mapped_column(Text, default="[]")   # 这次修了什么


class Subscription(Base):
    """Pod Cloud：订阅（按 Agent 数量分层计费：free 1-3 / pro 3+）。"""
    """Pod Cloud：订阅（按 Agent 数量分层计费：free 1-3 / pro 3+）。"""

    __tablename__ = "pod_subscriptions"

    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), primary_key=True)
    plan: Mapped[str] = mapped_column(String(16), default="free")  # free|pro
    agent_limit: Mapped[int] = mapped_column(Integer, default=3)
    renews_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    # 遗留列：早年 PSP 通道留下的，已无人写入。保留只为不动线上表结构
    # （SQLite 删列要重建表）；客户/订阅 id 一律看下面的通用列。
    legacy_psp_customer_id: Mapped[str] = mapped_column("stripe_customer_id", String(64), default="")
    provider_customer_id: Mapped[str] = mapped_column(String(64), default="")        # ctm_… / cus_…
    provider_subscription_id: Mapped[str] = mapped_column(String(64), default="")    # sub_… / 平台订阅 id
    billing_provider: Mapped[str] = mapped_column(String(16), default="")            # paddle
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class PodAlert(Base):
    """Pod Cloud：云端告警（与本地告警规则同构，sync 入库时重算）。"""

    __tablename__ = "pod_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    # NULL = 平台级告警（系统自检发现的云端问题，不挂在某个 agent 上）。
    # 老库这列是 NOT NULL，启动时的迁移会改掉（见 migrations.py）。
    agent_id: Mapped[int | None] = mapped_column(ForeignKey("pod_agents.id"), index=True, nullable=True)
    kind: Mapped[str] = mapped_column(String(32))  # secret_leak|injection_suspect|approval_timeout|deny_burst|selfcheck|agent_silence
    severity: Mapped[str] = mapped_column(String(8), default="medium")  # high|medium|low
    message: Mapped[str] = mapped_column(Text, default="")
    event_seq: Mapped[int] = mapped_column(Integer, default=0)
    state: Mapped[str] = mapped_column(String(16), default="open")  # open|acknowledged|resolved
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
