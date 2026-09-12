/**
 * CLI 与各包的英文词表：key = 中文原文（见 index.ts 的约定说明）。
 * 没在这里出现的字符串一律回显中文，所以新增输出不会因为漏翻译而空白。
 * `{name}` 是占位符，由 t() 的第二个参数填充。
 */
export const enUS: Record<string, string> = {
  // ── 通用 ──
  '已写入': 'Wrote',
  '未知模板 "{name}"，可用: {list}': 'Unknown template "{name}"; available: {list}',
  '✅ {path}: 策略检查通过（无问题）': '✅ {path}: policy checks passed (no issues)',
  '❌ 策略文件不可读: {error}': '❌ Cannot read the policy file: {error}',
  '✅ 未发现绕过网关的 MCP server（受管 {managed} 个）':
    '✅ No MCP servers bypass the gateway (managed: {managed})',
  '⚠️ {count} 个 MCP server 未经过 pod 网关（agent 可直连绕过策略/审计）:':
    '⚠️ {count} MCP servers do not go through the pod gateway (agents can bypass policy/audit):',
  '自检报告已写入: {path}': 'Self-check report written: {path}',
  '✅ 证据包有效（顶层哈希匹配，未被修改）: {path}':
    '✅ Evidence bundle is valid (top-level hash matches, unmodified): {path}',
  '❌ 证据包校验失败: {reason}': '❌ Evidence bundle verification failed: {reason}',
  '周报已写入: {path}': 'Weekly digest written: {path}',
  '草稿已写入: {path}': 'Draft written: {path}',
  '已恢复 {config} ← {backup}': 'Restored {config} ← {backup}',
  '  审计文件: {files} 个 | 策略快照: {policies} 个':
    '  Audit files: {files} | policy snapshots: {policies}',
  '  顶层哈希: {hash}': '  Top-level hash: {hash}',
  '  一页式报告: {path}': '  One-page report: {path}',
  '  验证: {cmd}': '  Verify: {cmd}',
  'rules:  {path}（判定规则归你，改这里即改判定；写错会 fail-closed 报错）':
    'rules:  {path} (the rules are yours — edit them to change verdicts; invalid rules fail closed)',
  'rules:  {path}（已存在，未覆盖）': 'rules:  {path} (already exists, left untouched)',
  '已完成': 'Done',
  '失败': 'Failed',
  '未找到': 'Not found',
  '跳过': 'Skipped',
  '下一步': 'Next step',
  '回滚': 'Rollback',
  '固定值（忽略）': 'Fixed value (ignored)',

  // ── init ──
  '初始化的 pod 目录不存在，无法写入示例策略': 'pod home does not exist, cannot write the example policy',

  // ── scan（获客楔子）──
  '发现 {count} 个 agent 平台（影子 agent 风险，见 T6）：{list}':
    'Found {count} agent platforms (shadow-agent risk, see T6): {list}',
  '{file} 不是合法 JSON，无法盘点 MCP server': '{file} is not valid JSON; cannot inventory MCP servers',
  'MCP server "{server}": {risk}': 'MCP server "{server}": {risk}',
  '{file} 中发现明文 {category}（{masked}）': 'Plaintext {category} found in {file} ({masked})',
  'npm 包 {pkg} 未锁定版本（供应链风险，见 T4）':
    'npm package {pkg} is not version-pinned (supply-chain risk, see T4)',
  'npm 包 {pkg} 使用 @latest 未锁定版本（供应链风险，见 T4）':
    'npm package {pkg} uses @latest (supply-chain risk, see T4)',

  // ── 审计与证据 ──
  '审计链校验通过': 'Audit chain verified',
  '全部审计记录可验证、不可篡改。': 'All audit records are verifiable and tamper-evident.',
  '证据包已导出: {path}': 'Evidence bundle exported: {path}',
  '证据包有效（顶层哈希匹配，未被修改）: {path}':
    'Evidence bundle is valid (top-level hash matches, unmodified): {path}',
  '审计文件: {files} 个 | 策略快照: {policies} 个':
    'Audit files: {files} | policy snapshots: {policies}',
  '顶层哈希: {hash}': 'Top-level hash: {hash}',
  '一页式报告: {path}': 'One-page report: {path}',
  '验证: {cmd}': 'Verify: {cmd}',

  // ── doctor ──
  'pod doctor — 环境与配置自检': 'pod doctor — environment and configuration self-check',
  '未发现绕过网关的 MCP server（受管 {managed} 个）':
    'No MCP servers bypass the gateway (managed: {managed})',
  '修复: pod onboard --yes（或先 pod onboard 看计划）':
    'Fix: pod onboard --yes (or run pod onboard first to preview the plan)',
  '未配置 cloud.json（pod sync/pull-policy 不可用，本地功能不受影响）':
    'cloud.json not configured (pod sync / pull-policy unavailable; local features unaffected)',
  '审计目录: {dir}': 'Audit directory: {dir}',

  // ── 策略 ──
  '先采集语料: pod record --config <mcp-manager.json> --server <name>':
    'Collect a corpus first: pod record --config <mcp-manager.json> --server <name>',
  'lint 提示:': 'lint findings:',
  '策略草稿已写入: {path}': 'Policy draft written: {path}',

  // ── onboard ──
  '没有可恢复的 pod 备份': 'No pod backup available to restore',
  '未发现可接管的 MCP 配置（支持 ~/.dsh/mcp-manager.json / ~/.claude.json / ~/.cursor/mcp.json）':
    'No MCP configuration found to take over (supports ~/.dsh/mcp-manager.json / ~/.claude.json / ~/.cursor/mcp.json)',
  '确认无误后执行: pod onboard --yes': 'Once it looks right: pod onboard --yes',

  // ── 控制平面命令 ──
  '基线已写入 {path}': 'Baseline written to {path}',
  '身份已建立：{agent}': 'Identity created: {agent}',
  '签名自检通过（fingerprint={fp}）': 'Signature self-check passed (fingerprint={fp})',
  '已熔断：{agent}': 'Quarantined: {agent}',
  '已解除熔断：{agent}': 'Quarantine lifted: {agent}',
  '没有处于熔断状态的 agent': 'No agents are quarantined',
  '没有已建立的 agent 身份（pod identity init --agent <name>）':
    'No agent identities yet (pod identity init --agent <name>)',
  '委托已签发：{parent} → {child}': 'Delegation issued: {parent} → {child}',
  '令牌已签发：{id} → agent={agent}': 'Grant issued: {id} → agent={agent}',
  '没有已签发的令牌（pod grant issue ...）': 'No grants issued yet (pod grant issue ...)',

  // ── 网关 ──
  '⚠️ HTTP 网关未设置 --auth-token：本机任意进程都可连接（建议设置）':
    '⚠️ HTTP gateway has no --auth-token: any local process can connect (set one)',
  'gateway ready on stdio; waiting for agent…': 'gateway ready on stdio; waiting for agent…',
  'agent 断开（stdin EOF），{label} 退出': 'agent disconnected (stdin EOF); {label} exiting',

  // ── 同步 ──
  'nothing to sync': 'nothing to sync',
  '云端无策略（可先在 Pod Cloud 策略中心创建模板或绑定本 agent）':
    'No policies in the cloud (create a template or bind this agent in Pod Cloud first)',

  // ── pod scan 报表 ──
  '# pod scan 报表 — 你 Agent 的信任基线': '# pod scan report — your agents’ trust baseline',
  '> 第一步：看清风险面。第二步：装闸门。第三步：每一步都有不可篡改的证据。':
    '> Step one: see the risk surface. Step two: put a gate in front. Step three: every action leaves tamper-evident evidence.',
  '扫描时间：{ts}': 'Scanned at: {ts}',
  '## 1. Agent 清单（影子 agent，T6）': '## 1. Agent inventory (shadow agents, T6)',
  '| 平台 | 已安装 |': '| Platform | Installed |',
  '## 2. MCP server（{count} 个）': '## 2. MCP servers ({count})',
  '未发现（DSH mcp-manager.json 不存在或为空）。': 'None found (DSH mcp-manager.json is missing or empty).',
  '| server | 来源 | 版本锁定 | 风险 |': '| server | source | version pinned | risk |',
  '本地 bin': 'local bin',
  '## 3. 密钥暴露（{count} 处）': '## 3. Secret exposure ({count} findings)',
  '✅ 未在 agent 配置中发现明文密钥。': '✅ No plaintext secrets found in agent configuration.',
  '| 位置 | 变量 | 类型 | 掩码 |': '| Location | Variable | Type | Masked |',
  '> 掩码仅显示前后几位。密钥管理建议：迁移到系统钥匙串 / secret 管理器后从配置中移除。':
    '> Only the first and last characters are shown. Recommended: move secrets to the system keychain / a secret manager and remove them from config files.',
  '## 4. 风险汇总': '## 4. Risk summary',
  '✅ 未发现风险。': '✅ No risks found.',
  'pod scan 只读、不联网、不上传任何数据。':
    'pod scan is read-only, does not use the network, and uploads nothing.',
  '**下一步**：`pod init --template baseline` 装上闸门，':
    '**Next step**: `pod init --template baseline` to put the gate in place —',
  '每次工具调用写入 SHA-256 哈希链——从今天起，你的 Agent 每一步都有不可篡改的证据。':
    'every tool call goes into a SHA-256 hash chain — from today on, every step your agents take is tamper-evident.',

  // ── pod posture 报表与判定 ──
  '# pod posture — 控制平面姿态': '# pod posture — control-plane posture',
  '生成时间：{ts}': 'Generated at: {ts}',
  '> ⚠️ 还没有基线：本次只做静态判定，漂移类检查（配置/记忆/钩子变更）未生效。':
    '> ⚠️ No baseline yet: this run only does static checks — drift detection (config / memory / hook changes) is inactive.',
  '> 先跑 `pod posture freeze` 记录当前姿态。':
    '> Run `pod posture freeze` first to record the current posture.',
  '汇总：🔴 {high} · 🟠 {medium} · 🟡 {low}': 'Summary: 🔴 {high} · 🟠 {medium} · 🟡 {low}',
  '✅ 未发现问题。': '✅ No findings.',
  '  - 位置：{subject}': '  - Where: {subject}',
  '  - 证据：{evidence}': '  - Evidence: {evidence}',
  '## 采集到的事实': '## Facts collected',
  '- 生命周期钩子：{n} 条': '- Lifecycle hooks: {n}',
  '- 冻结项配置：{n} 个存在': '- Frozen config files: {n} present',
  '- 记忆文件：{n} 个存在': '- Memory files: {n} present',
  '- MCP server：{n} 个': '- MCP servers: {n}',
  '- Agent 身份：{built}/{total} 已建立': '- Agent identities: {built}/{total} established',
  '- 委托链：{n} 条': '- Delegation chains: {n}',
  '- 审计链：{n} 条': '- Audit chains: {n}',
  '- 审计链：{n} 条（{broken} 条断裂）': '- Audit chains: {n} ({broken} broken)',
  '判定规则来自用户规则文件（默认 ~/.pod/rules.json），改规则即改判定。':
    'Verdicts come from your rules file (default ~/.pod/rules.json) — change the rules, change the verdicts.',
  '钩子命中风险规则': 'hook matched a risk rule',
  '钩子配置没有配套签名（{sig} 不存在），无法验证来源与时效':
    'Hook config has no signature ({sig} missing); origin and freshness cannot be verified',
  '基线之后新增了生命周期钩子（hook 以主机权限运行，需人工确认来源）':
    'A lifecycle hook was added since the baseline (hooks run with host privileges — verify the source)',
  '生命周期钩子内容与基线不一致（可能被插件更新静默改写）':
    'Hook content differs from the baseline (a plugin update may have rewritten it silently)',
  '基线中的钩子已消失（确认是否为正常卸载）':
    'A hook from the baseline is gone (confirm this was an intentional uninstall)',
  '基线之后新出现的被冻结配置文件（未经带外审批的变更）':
    'A frozen config file appeared after the baseline (a change without out-of-band approval)',
  '冻结项内容与基线不一致（审批模式、网关地址、权限范围可能被降级）':
    'Frozen config differs from the baseline (approval mode, gateway URL or scope may have been downgraded)',
  '基线中的配置文件已不存在': 'A config file from the baseline no longer exists',
  '长期记忆文件与基线不一致——记忆投毒会影响当前与后续会话，需人工确认写入来源':
    'A long-term memory file differs from the baseline — memory poisoning affects current and future sessions; verify the writer',
  'MCP server 来源未锁定版本（{source}）——上游更新会直接进入你的机器':
    'MCP server source is not version-pinned ({source}) — upstream updates land on your machine directly',
  '同名 MCP server 的启动命令/参数与基线不一致（可能被换成另一个包）':
    'A same-named MCP server has a different launch command/args than the baseline (possibly swapped for another package)',
  '这个 agent 没有独立密码学身份（共享凭证无法回答"是谁做的"）':
    'This agent has no independent cryptographic identity (shared credentials cannot answer “who did it”)',
  '身份存在但私钥缺失，无法签名（fingerprint={fp}）':
    'Identity exists but the private key is missing, so it cannot sign (fingerprint={fp})',
  '委托链校验失败：{errors}': 'Delegation chain failed verification: {errors}',
  '审计链在 seq {seq} 处断裂——追加会被拒绝，该链自断点起不再记录任何事件（云端也会以 409 拒收）':
    'Audit chain is broken at seq {seq} — appends are refused, so this chain records nothing after that point (the cloud also rejects it with 409)',

  // ── CLI 控制平面命令的明细行 ──
  'identity 已建立：{agent}': 'Identity created: {agent}',
  '  私钥: {path}（0600，不要外传）': '  Private key: {path} (mode 0600 — never share it)',
  '  能力: {caps}': '  Capabilities: {caps}',
  '  到期: {ts}': '  Expires: {ts}',
  '  到期: {ts}{single}': '  Expires: {ts}{single}',
  '（单次）': ' (single-use)',
  '（无）': '(none)',
  '  文件: {path}': '  File: {path}',
  '  跳: {hop}': '  Hop: {hop}',
  '  生效能力: {caps}': '  Effective capabilities: {caps}',
  '委托收窄校验：{parent} → {child}': 'Delegation narrowing: {parent} → {child}',
  '  父能力: {caps}': '  Parent capabilities: {caps}',
  '  子能力: {caps}': '  Child capabilities: {caps}',
  '  策略: {path}{dry}': '  Policy: {path}{dry}',
  '（dry-run 未写入）': ' (dry-run, not written)',
  '  跳过: {item}': '  Skipped: {item}',
  '  回滚: {cmd}': '  Roll back: {cmd}',
  'ℹ️ {count} 个 server 因非 stdio transport 暂不支持包装':
    'ℹ️ {count} servers cannot be wrapped yet (non-stdio transport)',
  'use: pod serve --policy <path> 加载策略': 'use: pod serve --policy <path> to load the policy',
  '{count} 项失败，其余已照常同步；修好上面这些再跑一次 pod sync。':
    '{count} items failed; everything else synced. Fix the ones above and run pod sync again.',
  '{reason}，{label} 退出': '{reason}; {label} exiting',

  // ── 控制平面命令的剩余明细行（posture freeze / grant / quarantine / anomaly / trace）──
  'capabilityRules: 从 {path} 加载 {n} 个工具的能力映射':
    'capabilityRules: loaded capability mappings for {n} tools from {path}',
  '⚠️ capabilityRules 已配置，但读取 {path} 失败：{err}；能力规则可能不生效':
    '⚠️ capabilityRules is configured but reading {path} failed: {err}; capability rules may not take effect',
  '⚠️ capabilityRules 已配置，但找不到 {path}；先运行 pod graph build 或 pod graph apply':
    '⚠️ capabilityRules is configured but {path} is missing; run pod graph build or pod graph apply first',
  '  冻结项 {configs} · 记忆 {memory} · 钩子 {hooks} · MCP 来源 {packages}':
    '  Frozen configs {configs} · memory {memory} · hooks {hooks} · MCP sources {packages}',
  '{consumed}到期 {ts}': '{consumed}expires {ts}',
  '（已消费）': '(consumed) ',
  '  ✗ 子 agent 扩大了权限: {caps}': '  ✗ child agent widened its capabilities: {caps}',
  '  ✗ 命中了不可委托能力: {caps}': '  ✗ hit a capability that cannot be delegated: {caps}',
  '  当前熔断 {n} 个 agent': '  {n} agents currently quarantined',
  '✅ 未发现信任传播异常（窗口 {min} 分钟）':
    '✅ No trust-propagation anomalies found (window {min} min)',
  '- {parent} → {child} [{caps}] @ {ts}': '- {parent} → {child} [{caps}] @ {ts}',
  '无能力': 'no capabilities',
  '- 无': '- none',
  '- 相关事件 {total} 条，其中被拒绝/阻断 {blocked} 条':
    '- {total} related events, {blocked} of them denied/blocked',
  '  - {ts} {agent} {server}.{tool} → {decision}（{reason}）':
    '  - {ts} {agent} {server}.{tool} → {decision} ({reason})',

  // ── 补完：已经包了 t() 但词表漏掉的串（带参数的注意占位符与调用点一致）──
  '   修复: pod onboard --yes（或先 pod onboard 看计划）':
    '   Fix: pod onboard --yes (or run pod onboard first to see the plan)',
  '  之后任何变更都会在 pod posture 里报出来（规则决定严重级别）。':
    '  Any later change will show up in pod posture (your rules decide the severity).',
  '  网关下一次调用即生效（无需重启）。':
    '  Takes effect on the next gateway call (no restart needed).',
  '## 下游（可能被影响的 agent）': '## Downstream (agents that may be affected)',
  '## 委托链（上游）': '## Delegation chain (upstream)',
  '## 审计时间线': '## Audit timeline',
  '- 没有记录到委托关系（该 agent 不是任何委托的接收方）':
    '- No delegations recorded (this agent is not the receiver of any delegation)',
  'token 只在本机终端出现；页面加载后会从地址栏移除。按 Ctrl+C 停止。':
    'The token appears only in this terminal; the page drops it from the URL once loaded. Press Ctrl+C to stop.',
  '{why}（规则 {rule}）：{command}': '{why} (rule {rule}): {command}',
  'ℹ️ 未配置 cloud.json（pod sync/pull-policy 不可用，本地功能不受影响）':
    'ℹ️ cloud.json is not configured (pod sync / pull-policy are unavailable; local features are unaffected)',
  '❌ cloud.json 解析失败': '❌ cloud.json could not be parsed',
  '下一步: 正常使用 agent 采集语料 → pod policy draft → 复核后切换执法模式':
    'Next: keep using your agent to collect traces → pod policy draft → review, then switch to enforcement mode',
  '回滚: pod onboard --revert': 'Roll back: pod onboard --revert',
  '没有可校验的身份（先 pod identity init --agent <name>）':
    'No identity to verify (run pod identity init --agent <name> first)',
  '签名无效：包内容与签名不匹配（可能被篡改），或公钥不对':
    'Invalid signature: the pack contents do not match the signature (possibly tampered with), or the public key is wrong',
  '签名无效：策略内容与签名不匹配（可能被篡改）':
    'Invalid signature: the policy contents do not match the signature (possibly tampered with)',
  '签名有效': 'Signature valid',
  '（已写入审计链）': '(written to the audit chain)',
  '基线文件损坏，无法解析：{path}（删掉它重新 pod posture freeze）':
    'Baseline file is corrupt and cannot be parsed: {path} (delete it and run pod posture freeze again)',
  '⚠️ {n} 条发现未能写入审计链：': '⚠️ {n} findings could not be written to the audit chain:',
  '没有身份（先 pod identity init）': 'No identity (run pod identity init first)',
  '私钥缺失': 'Private key is missing',
  '签名自检失败': 'Signature self-check failed',
  '熔断文件损坏：{file}': 'Quarantine file is corrupt: {file}',
  '✅ 审计目录: {path}': '✅ Audit directory: {path}',
  'ℹ️ 审计目录不存在（首次 record/serve 时创建）: {path}':
    'ℹ️ Audit directory does not exist yet (created on first record/serve): {path}',

  // ── pod coverage / pod timeline 报表 ──
  '# pod 受管覆盖率': '# pod managed coverage',
  '- 已受管：{n} 个': '- Managed: {n}',
  '- 未受管：{n} 个（可绕过策略/审计）': '- Unmanaged: {n} (these can bypass policy and audit)',
  '- 不支持包装：{n} 个（非 stdio transport）': '- Cannot be wrapped: {n} (non-stdio transport)',
  '## 未受管 MCP server': '## Unmanaged MCP servers',
  '| server | agent | 命令 | 配置 |': '| server | agent | command | config |',
  '修复：`pod onboard --yes` 接管，或 `pod onboard` 先看计划。':
    'Fix: run `pod onboard --yes` to take them over, or `pod onboard` to see the plan first.',
  '## 无法包装（v0 只支持 stdio）': '## Cannot be wrapped (v0 supports stdio only)',
  'pod coverage 只读配置，不修改任何文件。':
    'pod coverage only reads configuration; it does not modify any file.',
  '⚠️ 以下审计文件哈希链损坏（篡改或中断），已跳过：{list}':
    '⚠️ These audit files have a broken hash chain (tampering or truncation) and were skipped: {list}',
  '（无匹配事件）': '(no matching events)',

  // ── pod digest 周报 ──
  '本期没有工具调用记录': 'No tool calls recorded in this window',
  '本期平静：{n} 次调用，无拦截、无泄漏、无注入信号':
    'A quiet window: {n} calls, nothing blocked, no leaks, no injection signals',
  '拦截了 {n} 次被策略拒绝的调用': 'Blocked {n} calls that policy denied',
  '拦下 {n} 次疑似密钥外泄': 'Stopped {n} suspected secret leaks',
  '标记 {n} 次疑似提示注入': 'Flagged {n} suspected prompt injections',
  '{n} 次人工审批（批准 {approved}、拒绝 {denied}、超时 {timeout}）':
    '{n} manual approvals ({approved} approved, {denied} denied, {timeout} timed out)',
  '⚠️ {n} 个审计文件哈希链异常：{list}': '⚠️ {n} audit files have a broken hash chain: {list}',
  '⚠️ 发现 {n} 个未受管 MCP server（可绕过网关）：{list}':
    '⚠️ {n} unmanaged MCP servers found (they can bypass the gateway): {list}',
  '# pod 本地安全周报': '# pod local security digest',
  '统计窗口：{from} → {to}': 'Window: {from} → {to}',
  '## 本期结论': '## Takeaways',
  '- 暂无数据': '- No data yet',
  '## 调用总览': '## Call overview',
  '| 指标 | 数量 |': '| Metric | Count |',
  '| 总调用 | {n} |': '| Total calls | {n} |',
  '| record-only（未执法） | {n} |': '| record-only (not enforcing) | {n} |',
  '## 工具调用 Top': '## Top tools',
  '| server | tool | 调用 | 拦截 | 敏感 |': '| server | tool | calls | blocked | sensitive |',
  '## 审批与拦截': '## Approvals and blocks',
  '- 人工审批：{n} 次（批准 {approved} / 拒绝 {denied} / 超时 {timeout}）':
    '- Manual approvals: {n} ({approved} approved / {denied} denied / {timeout} timed out)',
  '- 审批人：{list}': '- Approvers: {list}',
  '- 拦截/告警事件：{n} 条': '- Blocked / alerted events: {n}',
  '## 审计完整性': '## Audit integrity',
  '- {server}.jsonl：{status}（{n} 条）': '- {server}.jsonl: {status} ({n} entries)',
  '✅ 哈希链完整': '✅ hash chain intact',
  '❌ 哈希链异常': '❌ hash chain broken',
  '## 受管覆盖率': '## Managed coverage',
  '- 已受管 server：{list}': '- Managed servers: {list}',
  '- 未受管 server：{list}': '- Unmanaged servers: {list}',
  '无': 'none',
  'pod digest 只读本地审计，不联网、不上传任何数据。':
    'pod digest only reads local audit data; it does not use the network and uploads nothing.',

  // ── pod ui 控制台（packages/console）──
  'pod 控制台（只读）已启动：{url}': 'pod console (read-only) started at {url}',
  '数据目录：{path}': 'Data directory: {path}',
  '收到 {signal}，正在停止控制台…': 'Received {signal}; stopping the console…',
  'pod ui listening on http://{host}:{port} (只读)': 'pod ui listening on http://{host}:{port} (read-only)',
  '文件超过 {max} 字节，已跳过': 'File is larger than {max} bytes; skipped',
  '未找到策略目录 {dir}：还没有登记任何 agent 策略（先跑 pod policy draft）':
    'Policy directory {dir} not found: no agent policies registered yet (run pod policy draft first)',
  '策略文件 {file} 无法解析，已跳过（{error}）': 'Policy file {file} could not be parsed; skipped ({error})',
  '策略文件 {file} 缺少 agent 字段，已跳过': 'Policy file {file} has no agent field; skipped',
  'agent "{agent}" 有多份策略（{first}、{second}），按后者展示':
    'Agent "{agent}" has more than one policy ({first}, {second}); showing the latter',
  '未找到审计目录 {dir}：还没有记录到真实调用（pod record / pod serve 会写入）':
    'Audit directory {dir} not found: no real calls recorded yet (pod record / pod serve write it)',
  '审计文件 {file} 超过 {max} 字节，已跳过（后续可做分页读取）':
    'Audit file {file} is larger than {max} bytes; skipped (paging is a later improvement)',
  '审计文件 {file} 读取失败，已跳过（{error}）': 'Audit file {file} could not be read; skipped ({error})',
  '审计文件中有 {n} 行无法解析，已跳过（哈希链可用 pod verify-audit 校验）':
    '{n} lines in the audit files could not be parsed; skipped (verify the hash chain with pod verify-audit)',
  '未找到 {path}：毒性链列需要先跑 pod graph toxic（能力图分析）':
    '{path} not found: the toxic-path column needs pod graph toxic (capability graph analysis) first',
  '{path} 无法解析为毒性链列表，已跳过': '{path} is not a parseable toxic-path list; skipped',
  '存在毒性链': 'Toxic path present',
  '{rule}：{explain}': '{rule}: {explain}',
  '来自 capability graph 的毒性链分析': 'From the capability graph toxic-path analysis',
  'MCP server 未锁定版本': 'MCP server is not version-pinned',
  '触发敏感路径拒绝': 'Triggered a sensitive-path denial',
  '审计中存在敏感路径拒绝': 'Sensitive-path denials appear in the audit',
  '未登记策略': 'No policy registered',
  '有真实调用记录，但 ~/.pod/policies 下没有它的策略——权限不受约束':
    'There are real calls, but no policy for it under ~/.pod/policies — its permissions are unconstrained',
  '未观测到调用': 'No calls observed',
  '策略已登记，但审计里没有它的调用记录（策略从行为编译，未观测 = 依据不足）':
    'A policy is registered, but the audit has no calls for it (policies compile from behaviour; no observations means weak evidence)',
  '本机发现 {n} 个 agent 平台尚未出现在策略或审计里：{list}':
    'Found {n} agent platforms on this machine that appear in neither policies nor audit: {list}',
  'agent 配置里有 {n} 处明文密钥（{list}），运行 pod scan 查看掩码报告':
    'Agent configuration holds {n} plaintext secrets ({list}); run pod scan for the masked report',

  // ── 证据包与审计自检报告（pod verify-audit / export-evidence）──
  '# pod 审计完整性自检报告': '# pod audit integrity report',
  '审计目录：{dir}': 'Audit directory: {dir}',
  '- 状态：{status}': '- Status: {status}',
  '❌ 哈希链断裂（seq {seq}）': '❌ hash chain broken (seq {seq})',
  '- 条目数：{n}': '- Entries: {n}',
  '- 链首 hash：{hash}': '- Head hash: {hash}',
  '- 链尾 hash：{hash}': '- Tail hash: {hash}',
  '（审计目录为空）': '(the audit directory is empty)',
  '**结论：{verdict}**': '**Conclusion: {verdict}**',
  '存在损坏记录，请排查。': 'Some records are damaged; please investigate.',
  'format 不是 pod-evidence-v1': 'format is not pod-evidence-v1',
  '顶层哈希不匹配（包被修改过）': 'Top-level hash mismatch (the bundle was modified)',
  '# AI Agent 操作审计证据包': '# AI agent action audit evidence bundle',
  '> 由 pod 本地生成，数据未上传任何第三方。导出时间：{ts}':
    '> Generated locally by pod; nothing was uploaded to any third party. Exported at: {ts}',
  '## 1. 覆盖范围': '## 1. Scope',
  '- 证据窗口：{from} → {to}': '- Evidence window: {from} → {to}',
  '- 审计记录：{n} 条（其中被阻断 {blocked} 条）': '- Audit records: {n} ({blocked} blocked)',
  '- 涉及工具：{n} 个': '- Tools involved: {n}',
  '- 决策分布：allow {allow} / approve {approve} / deny {deny}':
    '- Decision mix: allow {allow} / approve {approve} / deny {deny}',
  '## 2. 完整性自证': '## 2. Integrity self-proof',
  '- 顶层哈希：`{hash}`': '- Top-level hash: `{hash}`',
  '| 审计文件 | 哈希链 | 条目 | 链首 hash | 链尾 hash |':
    '| Audit file | Hash chain | Entries | Head hash | Tail hash |',
  '✅ 完整': '✅ intact',
  '❌ 断裂@{seq}': '❌ broken at {seq}',
  '## 3. 控制措施': '## 3. Controls',
  '| 控制项 | pod 机制 | 本证据包中的对应记录 |': '| Control | pod mechanism | Where it shows in this bundle |',
  '| 工具调用授权 | 策略引擎，`deny > approve > allow`，未授权默认拒绝 | 每条记录的 decision / reason |':
    '| Tool-call authorisation | Policy engine, `deny > approve > allow`, unlisted calls denied by default | decision / reason on every record |',
  '| 高风险操作审批 | 审批闸门，超时按拒绝处理（fail-closed） | approver / reason 字段 |':
    '| Approval for high-risk actions | Approval gate, timeouts count as denial (fail-closed) | approver / reason fields |',
  '| 审计不可篡改 | SHA-256 哈希链，逐条前后链接 | 上方完整性自证 + 链首/链尾 hash |':
    '| Tamper-evident audit | SHA-256 hash chain, each record linked to the previous | integrity self-proof above + head/tail hashes |',
  '| 敏感数据防外泄 | 敏感路径输入拦截 + 输出密钥正则拦截 | 被阻断记录（blocked） |':
    '| Leak prevention | Sensitive-path input blocking + secret regex on output | blocked records |',
  '| 供应链来源校验 | server 启动来源白名单（command/package/version） | 策略快照中的 source 字段 |':
    '| Supply-chain origin checks | Allowlist on server launch source (command/package/version) | source field in the policy snapshot |',
  '## 4. 独立验证方式': '## 4. How to verify independently',
  '# 验证证据包未被修改': '# verify the bundle has not been modified',
  '# 重新校验原始审计哈希链': '# re-verify the original audit hash chain',
  'pod 只记录工具调用的哈希与元数据，不存储参数/输出原文。':
    'pod records only hashes and metadata of tool calls; it never stores argument or output bodies.',
  '- Agent：{list}': '- Agent: {list}',
  '- MCP server：{list}': '- MCP servers: {list}',

  // ── pod graph（能力图报表与 CLI 输出）──
  '# pod graph（{source}）': '# pod graph ({source})',
  'agent：{agents} · server：{servers} · tool：{tools}':
    'agents: {agents} · servers: {servers} · tools: {tools}',
  '配置指纹：{fp}': 'Config fingerprint: {fp}',
  '## 警告': '## Warnings',
  '（{where}）': ' ({where})',
  '# pod graph toxic — 毒性路径': '# pod graph toxic — toxic paths',
  '阈值：min-confidence={min} · max-paths={max}': 'Thresholds: min-confidence={min} · max-paths={max}',
  '## 风险排序（按 score）': '## Risk ranking (by score)',
  '| score | 风险 | 规则 | source → sink | 路径数 | 跨 agent | 主要理由 |':
    '| score | risk | rule | source → sink | paths | cross-agent | main reasons |',
  '## 断链建议': '## How to break the chain',
  '### {id}（score {score}，{rule}）{verdict}': '### {id} (score {score}, {rule}){verdict}',
  '**能力级建议**：{reason}': '**Capability-level advice**: {reason}',
  '示例改动（前 {n} 个）：': 'Example changes (first {n}):',
  '收紧 {side} 的 {n} 个工具，覆盖 {paths} 条路径：':
    'Tighten {n} {side} tools, covering {paths} paths:',
  '未发现毒性路径。': 'No toxic paths found.',
  '## 高危（{n}）': '## High ({n})',
  '## 中危（{n}）': '## Medium ({n})',
  '> 还有 {n} 条路径未显示；用 --max-paths 调整。':
    '> {n} more paths are not shown; adjust with --max-paths.',
  '# pod graph diff — 潜在 vs 观测': '# pod graph diff — potential vs observed',
  '潜在工具：{potential} · 观测工具：{observed}':
    'Potential tools: {potential} · observed tools: {observed}',
  '## 权限过载（潜在 − 实际）：{n}': '## Over-privileged (potential − observed): {n}',
  '| server | tool | agents | 能力 |': '| server | tool | agents | capabilities |',
  '| … | 还有 {n} 条 | … | … |': '| … | {n} more | … | … |',
  '## 影子能力（实际 − 潜在）：{n}': '## Shadow capabilities (observed − potential): {n}',
  '| server | tool | agents | 能力 | 调用 |': '| server | tool | agents | capabilities | calls |',
  '| … | 还有 {n} 条 | … | … | … |': '| … | {n} more | … | … | … |',
  '### {id}  {rule}（{kind}，置信度 {confidence}）':
    '### {id}  {rule} ({kind}, confidence {confidence})',
  '  说明：{explain}': '  Explanation: {explain}',
  '  建议：将 {target} 从 {from} 改为 {to}': '  Suggestion: change {target} from {from} to {to}',
  '  理由：{rationale}': '  Why: {rationale}',
  '\n已写入：{path}\n': '\nWritten to: {path}\n',
  'graph 生成于 {ts}，超过 7 天，结论仅供参考':
    'Graph was generated at {ts}; older than 7 days, so treat the findings as indicative',
  '\n观测记录：{n} 条，已写入：{path}\n': '\n{n} observations written to: {path}\n',
  'observed graph not found: {path}（先运行 pod graph observe）\n':
    'observed graph not found: {path} (run pod graph observe first)\n',
  '跳过 {agent}：没有观测数据（先 pod record/observe）\n':
    'Skipping {agent}: no observations yet (run pod record/observe first)\n',
  '没有任何 agent 有观测数据；先运行 pod record 或 pod graph observe\n':
    'No agent has observations yet; run pod record or pod graph observe first\n',
  '已写入 {path}：capabilityMap 覆盖 {n} 个工具\n':
    'Written to {path}: capabilityMap covers {n} tools\n',
  '{id}  {rule}（score {score} / {risk}，路径 {count}，跨 agent {cross}）':
    '{id}  {rule} (score {score} / {risk}, paths {count}, cross-agent {cross})',
  '断链（能力级）：{reason}': 'Break the chain (capability level): {reason}',
  '示例改动：': 'Example changes:',
  '断链：收紧 {side} 的 {n} 个工具': 'Break the chain: tighten {n} {side} tools',
  '说明:   {explain}': 'Explanation:   {explain}',
  '证据:   {evidence}': 'Evidence:   {evidence}',
  '建议:   {target} {from} → {to}': 'Suggestion:   {target} {from} → {to}',
  '{id}  {rule}（{kind}，置信度 {confidence}）': '{id}  {rule} ({kind}, confidence {confidence})',
}
