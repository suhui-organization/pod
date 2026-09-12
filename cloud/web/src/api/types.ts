export interface ApiError {
  code?: string
  message?: string
}

export interface AuthResponse {
  access_token: string
  refresh_token: string
  expires_in_minutes: number
  email: string
  tenant: TenantInfo
}

export interface TenantInfo {
  id: number
  name: string
  slug: string
  plan: string
}

export interface UserItem {
  id: number
  email: string
  full_name: string
  role: string
  is_active: boolean
  created_at?: string
}

/** GET/PUT /auth/me 的响应：登录者自己的身份 + 资料 */
export interface MeProfile {
  id: number
  email: string
  full_name: string
  tenant_id: number
  role: string
  client?: string
  /** 上次改密时间(ISO)；null = 从未改过。用于「哪些会话已被踢掉」的可核查说明 */
  password_changed_at: string | null
}

export interface PasswordChangeResult {
  access_token: string
  refresh_token: string
  expires_in_minutes: number
  user: MeProfile
}

export interface AgentItem {
  id: number
  name: string
  platform: string
  status: 'online' | 'offline'
  last_seen_at: string | null
  event_count: number
  created_at: string
}

export interface AgentCreateResult {
  agent: AgentItem
  sync_token: string
}

export interface PolicyItem {
  id: number
  name: string
  agent_id: number | null
  policy_json: string
  note: string
  version: string
  created_at: string
}

export interface DashboardSummary {
  agents: { total: number; online: number }
  events: {
    total: number
    by_decision: Record<string, number>
    by_outcome: Record<string, number>
    by_server: Record<string, number>
    by_tool: Array<{ tool: string; events: number }>
    // events/control 是累计值（只增不减，看起来永远不动）；
    // events_recent/control_recent 是近 7 天，才是"活跃度"该有的口径。
    per_agent: Array<{
      agent: string
      events: number
      events_recent: number
      control: number
      control_recent: number
    }>
    /** 控制平面事件累计总数（与工具调用分开统计） */
    control_total: number
    /** 近 7 天控制平面事件按 kind 聚合 */
    control_by_kind_7d: Record<string, number>
    hourly_24h: Array<{ hour: string; events: number }>
  }
  trend_7d: Array<{ date: string; events: number }>
  alerts: {
    open: number
    acknowledged: number
    resolved: number
    open_high: number
    by_severity: Record<string, number>
    by_kind: Array<{ kind: string; count: number }>
    trend_7d: Array<{ date: string; count: number }>
  }
  alerts_recent: Array<{ id: number; kind: string; severity: string; message: string; created_at: string }>
  plan: string
  agent_limit: number
}

export interface SubscriptionInfo {
  plan: string
  agent_limit: number
  agent_count: number
  renews_at: string | null
  /** 支付通道是否已开通（后端按当前计费平台判定） */
  billing_configured?: boolean
  /** 当前计费平台 id：stripe / paddle / creem / waffo */
  billing_provider?: string
  /** Paddle.js 用的公开 token（仅 provider=paddle 时返回） */
  paddle_client_token?: string
  /** sandbox | live */
  paddle_environment?: string
  /** @deprecated 旧字段，等价于 billing_configured */
  stripe_configured?: boolean
}

/** 一个可选的模型来源（后端 PROVIDERS，界面不自己维护候选列表） */
export interface LlmProvider {
  id: string
  label: string
  default_model: string
  needs_key: boolean
  needs_base_url: boolean
  note: string
}

/** 一个依赖模型的 AI 功能：未配置时会怎样退化 */
export interface LlmFeature {
  id: string
  name: string
  where: string
  degraded: string
}

export interface LlmSettings {
  provider: string
  model: string
  base_url: string
  api_key_set: boolean
  api_key_hint: string
  /** 当前配置能否直接调用；false 时 reason 说明缺什么 */
  configured: boolean
  reason: string
  /** 实际会用的 provider/model/endpoint（含环境变量兜底与默认模型） */
  effective: {
    provider?: string
    model?: string
    endpoint?: string
    key_source?: 'tenant' | 'env'
    key_hint?: string
  }
  providers: LlmProvider[]
  features: LlmFeature[]
}

export interface LlmTestResult {
  ok: boolean
  provider: string
  model: string
  endpoint: string
  latency_ms: number
  error: string
  sample: string
}
