import { http } from './client'
import type {
  AgentCreateResult,
  AgentItem,
  AuthResponse,
  DashboardSummary,
  HardenReportDetail,
  HardenReportItem,
  LlmSettings,
  LlmTestResult,
  MeProfile,
  PasswordChangeResult,
  PolicyItem,
  RulePackItem,
  SubscriptionInfo,
  TenantInfo,
  UserItem,
} from './types'

export const api = {
  // ---- 认证 ----
  authConfig(): Promise<{
    is_private: boolean
    /** 本部署是否启用计费（前端据此隐藏订阅入口） */
    billing_enabled: boolean
    billing_provider: string
    /** 找回密码的投递方式：email=已配 SMTP；log=链接写服务端日志 */
    password_reset: 'email' | 'log'
    password_reset_minutes: number
    /** 后端镜像的构建标识（tag）；与前端自己的 tag 对照即可看出是否同一次发布 */
    build: string
    /** 后端镜像来自哪个 commit；前后端是否同一次发布按它判断（tag 每镜像独立，不可比） */
    build_commit?: string
  }> {
    return http.get('/api/v1/auth/config').then((r) => r.data)
  },
  /** 申请找回密码链接。无论邮箱是否注册，响应都一样（防账号枚举） */
  forgotPassword(email: string): Promise<{ ok: boolean }> {
    return http.post('/api/v1/auth/forgot-password', { email }).then((r) => r.data)
  },
  /** 用邮件/日志里的一次性令牌换新密码；成功后该账号所有旧会话失效 */
  resetPassword(token: string, newPassword: string): Promise<{ ok: boolean }> {
    return http
      .post('/api/v1/auth/reset-password', { token, new_password: newPassword })
      .then((r) => r.data)
  },
  register(email: string, password: string, fullName = '', tenantName = ''): Promise<AuthResponse> {
    return http
      .post('/api/v1/auth/register', { email, password, full_name: fullName, tenant_name: tenantName })
      .then((r) => r.data)
  },
  login(email: string, password: string): Promise<AuthResponse> {
    return http.post('/api/v1/auth/login', { email, password }).then((r) => r.data)
  },
  refresh(refreshToken: string): Promise<{ access_token: string }> {
    return http.post('/api/v1/auth/refresh', { refresh_token: refreshToken }).then((r) => r.data)
  },
  me(): Promise<MeProfile> {
    return http.get('/api/v1/auth/me').then((r) => r.data)
  },
  /** 本人改资料(目前只有姓名)。写操作只开自己这一条,不需要 admin */
  updateProfile(fullName: string): Promise<MeProfile> {
    return http.put('/api/v1/auth/me', { full_name: fullName }).then((r) => r.data)
  },
  /** 本人改密:要验旧密码;成功后其它会话全部失效,响应里带回本会话的新 token */
  changePassword(oldPassword: string, newPassword: string): Promise<PasswordChangeResult> {
    return http
      .post('/api/v1/auth/me/password', { old_password: oldPassword, new_password: newPassword })
      .then((r) => r.data)
  },
  tenantMe(): Promise<TenantInfo & { members: number; my_role?: string }> {
    return http.get('/api/v1/tenants/me').then((r) => r.data)
  },
  getMyPreferences(): Promise<{ preferences: Record<string, unknown> }> {
    return http.get('/api/v1/auth/me/preferences').then((r) => r.data)
  },
  putMyPreferences(body: { preferences: Record<string, unknown> }): Promise<{ preferences: Record<string, unknown> }> {
    return http.put('/api/v1/auth/me/preferences', body).then((r) => r.data)
  },

  // ---- 成员管理 ----
  users(): Promise<UserItem[]> {
    return http.get('/api/v1/users').then((r) => r.data)
  },
  createUser(body: { email: string; password: string; full_name?: string; role?: string }): Promise<UserItem> {
    return http.post('/api/v1/users', body).then((r) => r.data)
  },
  updateUser(userId: number, body: { full_name?: string; role?: string; is_active?: boolean }): Promise<UserItem> {
    return http.patch(`/api/v1/users/${userId}`, body).then((r) => r.data)
  },
  deactivateUser(userId: number): Promise<{ deactivated: number }> {
    return http.delete(`/api/v1/users/${userId}`).then((r) => r.data)
  },

  // ---- Agent 资产（Pod Cloud）----
  agents(): Promise<{ agents: AgentItem[] }> {
    return http.get('/api/v1/agents').then((r) => r.data)
  },
  registerAgent(body: { name: string; platform?: string }): Promise<AgentCreateResult> {
    return http.post('/api/v1/agents', body).then((r) => r.data)
  },
  rotateToken(agentId: number): Promise<{ sync_token: string }> {
    return http.post(`/api/v1/agents/${agentId}/rotate-token`).then((r) => r.data)
  },
  removeAgent(agentId: number): Promise<{ removed: number }> {
    return http.delete(`/api/v1/agents/${agentId}`).then((r) => r.data)
  },

  // ---- 策略中心 ----
  policies(): Promise<{ policies: PolicyItem[] }> {
    return http.get('/api/v1/policies').then((r) => r.data)
  },
  generatePolicy(description: string): Promise<{ policy: Record<string, unknown>; policy_json: string; model: string; explanation?: string; saved: boolean }> {
    return http.post('/api/v1/policies/generate', { description }).then((r) => r.data)
  },
  digestNow(): Promise<{ pushed: boolean; alerts_count: number; date: string }> {
    return http.post('/api/v1/alerts/digest-now').then((r) => r.data)
  },
  policyTemplates(): Promise<{ templates: Array<{ id: string; name: string; desc: string; default_decision: string; allow: string[]; deny: string[]; approve: string[]; sensitive_paths: number }> }> {
    return http.get('/api/v1/policies/templates').then((r) => r.data)
  },
  policyVersions(policyId: number): Promise<{ policy_id: number; current_version: string; versions: Array<{ version: number; policy_json: string; note: string; created_at: string }> }> {
    return http.get(`/api/v1/policies/${policyId}/versions`).then((r) => r.data)
  },
  revertPolicy(policyId: number, version: number): Promise<{ policy: PolicyItem; reverted_to: number }> {
    return http.post(`/api/v1/policies/${policyId}/revert`, { version }).then((r) => r.data)
  },
  applyPolicyTemplate(template: string, agentId: number | null): Promise<{ applied: boolean; template: string }> {
    return http.post('/api/v1/policies/apply-template', { template, agent_id: agentId }).then((r) => r.data)
  },
  createPolicy(body: { name: string; policy_json: string; agent_id?: number | null; note?: string }): Promise<{ policy: PolicyItem }> {
    return http.post('/api/v1/policies', body).then((r) => r.data)
  },
  updatePolicy(policyId: number, body: { name: string; policy_json: string; agent_id?: number | null; note?: string }): Promise<{ policy: PolicyItem }> {
    return http.put(`/api/v1/policies/${policyId}`, body).then((r) => r.data)
  },
  deletePolicy(policyId: number): Promise<{ removed: number }> {
    return http.delete(`/api/v1/policies/${policyId}`).then((r) => r.data)
  },

  // ---- 仪表盘 ----
  dashboardSummary(): Promise<DashboardSummary> {
    return http.get('/api/v1/dashboard/summary').then((r) => r.data)
  },

  // ---- 订阅 ----
  subscription(): Promise<SubscriptionInfo> {
    return http.get('/api/v1/subscription').then((r) => r.data)
  },
  updatePlan(plan: 'free' | 'pro'): Promise<{ plan: string; agent_limit: number }> {
    return http.post('/api/v1/subscription/plan', { plan }).then((r) => r.data)
  },
  checkout(plan: 'free' | 'pro'): Promise<{
    checkout_url: string
    /** Paddle：交易 id（开 overlay 要用它） */
    session_id?: string
    transaction_id?: string
    /** Paddle 专用：支付成功后跳回的地址，由前端在 Paddle.js 里指定 */
    success_url?: string
    provider?: string
  }> {
    return http.post('/api/v1/subscription/checkout', { plan }).then((r) => r.data)
  },

  // ---- 合规报告 ----
  gdprReport(days = 30): Promise<{ tenant: { name: string }; agents: unknown[]; activities: { total_events: number; by_decision: Record<string, number>; approvals: Array<{ approver: string; reason: string; count: number }> } }> {
    return http.get(`/api/v1/reports/gdpr?days=${days}`).then((r) => r.data)
  },
  timeline(params: { limit?: number; minutes?: number; server?: string; tool?: string; agent_id?: number }): Promise<{
    events: Array<{ id: number; agent: string; agent_id: number; ts: string; server: string; tool: string; args_hash: string; decision: string; outcome: string; approver: string; reason: string; policy_version: string; enforced: boolean; seq: number }>
  }> {
    const q = new URLSearchParams()
    if (params.limit) q.set('limit', String(params.limit))
    if (params.minutes) q.set('minutes', String(params.minutes))
    if (params.server) q.set('server', params.server)
    if (params.tool) q.set('tool', params.tool)
    if (params.agent_id) q.set('agent_id', String(params.agent_id))
    return http.get(`/api/v1/timeline?${q}`).then((r) => r.data)
  },
  // ---- 控制平面（钩子/配置冻结/记忆/包来源/身份/委托/令牌/熔断）----
  // 与 timeline（agent 做了什么）并列：这里回答"agent 的运行环境被谁改过"
  controlEvents(params: { limit?: number; minutes?: number; kind?: string; agent_id?: number } = {}): Promise<{
    events: Array<{
      id: number
      agent: string
      agent_id: number
      kind: string
      category: string
      severity: string
      ts: string
      seq: number
      decision: string
      outcome: string
      reason: string
      args_hash: string
      chain: string
      prev_hash: string
      hash: string
    }>
    severity_source: string
  }> {
    const q = new URLSearchParams()
    if (params.limit) q.set('limit', String(params.limit))
    if (params.minutes) q.set('minutes', String(params.minutes))
    if (params.kind) q.set('kind', params.kind)
    if (params.agent_id) q.set('agent_id', String(params.agent_id))
    return http.get(`/api/v1/control-events?${q}`).then((r) => r.data)
  },
  controlEventSummary(minutes = 0): Promise<{ total: number; by_kind: Record<string, number>; by_severity: Record<string, number> }> {
    const q = minutes > 0 ? `?minutes=${minutes}` : ''
    return http.get(`/api/v1/control-events/summary${q}`).then((r) => r.data)
  },
  /** 巡检历史（新→旧）+ 自动巡检策略；不传 withChecks 时只回摘要 */
  selfcheckHistory(limit = 10, withChecks = false): Promise<{
    runs: Array<{
      id: number
      trigger: 'manual' | 'daily'
      started_at: string
      finished_at: string
      summary: {
        pass: number
        warn: number
        fail: number
        repaired: number
        /** 这项不适用（例如自托管没配模型），不是故障 */
        info?: number
        /** 这次巡检对告警列表做了什么（历史里附带的计数） */
        alerts_created?: number
        alerts_resolved?: number
      }
      repairs: string[]
      checks?: Array<{
        id: string
        title: string
        status: 'pass' | 'warn' | 'fail' | 'info'
        detail: string
        hint: string
        repairable: boolean
        repaired: boolean
      }>
    }>
    schedule: { enabled: boolean; hour: number; repair: boolean; notify: string }
  }> {
    const q = new URLSearchParams({ limit: String(limit) })
    if (withChecks) q.set('with_checks', 'true')
    return http.get(`/api/v1/selfcheck/history?${q}`).then((r) => r.data)
  },
  // ---- 系统自检 / 自修复 ----
  selfcheck(repair = false): Promise<{
    started_at: string
    finished_at: string
    locale: string
    summary: { pass: number; warn: number; fail: number; info?: number; repaired: number }
    /** 这次自检对告警列表做了什么：新开的 / 自动关闭的告警 id */
    alerts: { created: number[]; resolved: number[] }
    repairs: string[]
    checks: Array<{
      id: string
      title: string
      status: 'pass' | 'warn' | 'fail' | 'info'
      detail: string
      hint: string
      repairable: boolean
      repaired: boolean
    }>
  }> {
    return http.post('/api/v1/selfcheck/run', { repair }).then((r) => r.data)
  },
  traces(params: { minutes?: number; user_id?: number; agent_id?: number } = {}): Promise<{
    gap_minutes: number
    users: Array<{ id: number; email: string; full_name: string; role: string }>
    // 窗口外的最新一条审计（空态提示用）：last_event_at=调用真实发生时间，last_synced_at=同步上云时间
    last_event_at: string | null
    last_synced_at: string | null
    tasks: Array<{
      id: string
      agent_id: number
      agent: string
      platform: string
      owner_id: number | null
      owner_name: string
      owner_email: string
      started_at: string
      ended_at: string
      call_count: number
      duration_seconds: number
      avg_gap_seconds: number
      max_gap_seconds: number
      decisions: Record<string, number>
      calls: Array<{
        id: number
        seq: number
        ts: string
        tool: string
        server: string
        decision: string
        outcome: string
        approver: string
        reason: string
        args_hash: string
        policy_version: string
        inter_gap_seconds: number | null
      }>
    }>
  }> {
    const q = new URLSearchParams()
    if (params.minutes) q.set('minutes', String(params.minutes))
    if (params.user_id) q.set('user_id', String(params.user_id))
    if (params.agent_id) q.set('agent_id', String(params.agent_id))
    return http.get(`/api/v1/traces?${q}`).then((r) => r.data)
  },
  // agent_id 为 null = 平台级告警（系统自检），agent 字段会显示成 Pod Cloud
  alerts(limit = 50, kind?: string, severity?: string, state?: string): Promise<{ alerts: Array<{ id: number; agent: string; agent_id: number | null; kind: string; severity: string; message: string; event_seq: number; state: string; created_at: string }> }> {
    const params = new URLSearchParams({ limit: String(limit) })
    if (kind) params.set('kind', kind)
    if (severity) params.set('severity', severity)
    if (state) params.set('state', state)
    return http.get(`/api/v1/alerts?${params}`).then((r) => r.data)
  },
  updateAlertState(alertId: number, state: string): Promise<{ id: number; state: string }> {
    return http.put(`/api/v1/alerts/${alertId}/state`, { state }).then((r) => r.data)
  },
  alertSummary(hours = 24): Promise<{ summary: string; model: string; alerts_count: number; ai_generated: boolean }> {
    return http.post(`/api/v1/alerts/summarize?hours=${hours}`).then((r) => r.data)
  },
  batchAlertState(ids: number[], state: string): Promise<{ updated: number }> {
    return http.post(`/api/v1/alerts/batch-state?state=${state}`, ids).then((r) => r.data)
  },
  settings(): Promise<{
    provider: string
    api_key_set: boolean
    model: string
    mcp_commands: string
    datasources: Record<string, unknown>
    tool_policy: Record<string, unknown>
    alert_webhook: { enabled: boolean; channel: string; url_set: boolean; min_severity: string }
    alert_smtp: { enabled: boolean; host: string; port: number; user_set: boolean; from_addr: string; to_addrs: string; tls: boolean }
    alert_rules: { deny_burst_threshold?: number; burst_window_seconds?: number; spike_threshold?: number; silence_hours?: number }
    ai_digest: { enabled: boolean }
  }> {
    return http.get('/api/v1/settings').then((r) => r.data)
  },
  updateSettings(body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return http.put('/api/v1/settings', body).then((r) => r.data)
  },

  // ---- AI 模型（设置 → AI 模型）----
  llmSettings(): Promise<LlmSettings> {
    return http.get('/api/v1/settings/llm').then((r) => r.data)
  },
  saveLlmSettings(body: {
    provider?: string
    model?: string
    base_url?: string
    api_key?: string
  }): Promise<LlmSettings> {
    return http.put('/api/v1/settings/llm', body).then((r) => r.data)
  },
  testLlm(body: { provider?: string; model?: string; base_url?: string; api_key?: string }): Promise<LlmTestResult> {
    return http.post('/api/v1/settings/llm/test', body).then((r) => r.data)
  },

  // ---- 熔断（web → 机器：期望状态，机器 pod sync 时收敛）----
  quarantineAgent(agentId: number, reason: string): Promise<{ agent: AgentItem }> {
    return http.post(`/api/v1/agents/${agentId}/quarantine`, { reason }).then((r) => r.data)
  },
  /** 解除熔断：只能解除云端下的那一条，人工在机器上手工加的熔断不受影响 */
  releaseAgent(agentId: number): Promise<{ agent: AgentItem }> {
    return http.delete(`/api/v1/agents/${agentId}/quarantine`).then((r) => r.data)
  },
  gdprReportMarkdown(days = 30): Promise<string> {
    return http.get(`/api/v1/reports/gdpr?days=${days}&format=markdown`, { responseType: 'text' }).then((r) => r.data)
  },

  // ---- 规则包（订阅式加固：发布 → 机器 `pod rules pull --from-cloud` 拉取）----
  rulePacks(): Promise<{ packs: RulePackItem[] }> {
    return http.get('/api/v1/rules/packs').then((r) => r.data)
  },
  /** 发布并立即生效（上一版自动置为非生效） */
  publishRulePack(body: { pack_json: string; note?: string }): Promise<{ pack: RulePackItem }> {
    return http.post('/api/v1/rules/packs', body).then((r) => r.data)
  },
  /** 撤回/回滚到指定版本（保留历史，不删除） */
  activateRulePack(packId: number): Promise<{ pack: RulePackItem }> {
    return http.post(`/api/v1/rules/packs/${packId}/activate`, {}).then((r) => r.data)
  },

  // ---- 加固报告（pod harden --upload 的交付物）----
  hardenReports(agentId?: number): Promise<{ reports: HardenReportItem[] }> {
    const q = agentId ? `?agent_id=${agentId}` : ''
    return http.get(`/api/v1/harden/reports${q}`).then((r) => r.data)
  },
  hardenReport(id: number): Promise<{ report: HardenReportDetail }> {
    return http.get(`/api/v1/harden/reports/${id}`).then((r) => r.data)
  },
}
