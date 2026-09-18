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
  '**想把 16 类 harness 都过一遍**：`pod guard scan`（只读，输出「先做这三件事」与逐条处置命令）。':
    '**Want all 16 harnesses checked**: `pod guard scan` (read-only; opens with "do these three things first" and a runnable command per item).',
  '**要交给客户或审计方**：`pod harden --out ~/pod-audit-<日期>`（可交付、对方能用 `pod harden --verify` 自己验的报告目录）。':
    '**Handing this to a client or auditor**: `pod harden --out ~/pod-audit-<date>` (a deliverable report directory the recipient verifies with `pod harden --verify`).',

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
  '下一步：': 'Next steps:',
  '数据目录：{path}': 'Data directory: {path}',
  '收到 {signal}，正在停止控制台…': 'Received {signal}; stopping the console…',
  'pod ui listening on http://{host}:{port}（只读）': 'pod ui listening on http://{host}:{port} (read-only)',
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

  // ── graph 的理由与说明文案（explain / rationale / baseline / retention）──
  '敏感数据可被读取，同时存在外发通道，构成数据外泄链。':
    'Sensitive data can be read and there is an outbound channel, forming a data-exfiltration chain.',
  '可读外部不可信内容，同时可执行命令，构成注入→执行链。':
    'Untrusted external content can be read and commands can be executed, forming an injection→execution chain.',
  '可读外部内容并可外发，存在被注入后外泄的风险。':
    'External content can be read and data can be sent out, so an injection could lead to exfiltration.',
  '可获取凭据并具备执行/外发能力，构成凭据滥用链。':
    'Credentials can be read and there is execution/egress capability, forming a credential-abuse chain.',
  '{sourceAgent} 的 {sourceTool} 具备 {sourceCapability}，{sinkAgent} 的 {sinkTool} 具备 {sinkCapability}；{rationale}':
    '{sourceAgent} {sourceTool} has {sourceCapability}, and {sinkAgent} {sinkTool} has {sinkCapability}; {rationale}',
  '{agent} 同时具备写能力与破坏性工具 {tool}': '{agent} has both write access and the destructive tool {tool}',
  '{agent} 同时具备写能力与破坏性工具，存在不可逆破坏风险。':
    '{agent} has both write access and destructive tools, risking irreversible damage.',
  'sink 是链路末端；改为审批可保留可用性，同时阻断自动外发。':
    'The sink is the end of the chain; requiring approval keeps it usable while stopping automatic egress.',
  'sink 已需审批，收紧 source 可进一步降低自动触发的风险。':
    'The sink already needs approval; tightening the source further reduces automatic triggering.',
  '两端均已需审批；若要彻底断链，需 deny source（会改变工作流，需人工确认）。':
    'Both ends already need approval; breaking the chain completely means denying the source (this changes the workflow and needs human sign-off).',
  '断链：收紧 sink {server}.{tool}（{capability}）': 'Break the chain: tighten sink {server}.{tool} ({capability})',
  '断链：收紧 source {server}.{tool}（{capability}）':
    'Break the chain: tighten source {server}.{tool} ({capability})',
  '工具级最小割需要改 {n} 个 {side}；建议加入 capabilityRules.approve: ["{capability}"]，并运行 pod graph apply 生成 capabilityMap':
    'A tool-level min-cut means changing {n} {side} tools; consider adding capabilityRules.approve: ["{capability}"] and running pod graph apply to generate the capabilityMap',
  'allow {allow} · approve {approve} · deny {deny} · 省略（权限过载）{omitted}':
    'allow {allow} · approve {approve} · deny {deny} · omitted (over-privileged) {omitted}',
  '## 影子能力（需人工确认）：{n}': '## Shadow capabilities (need human review): {n}',
  '- {server}.{tool}（{caps}，调用 {n}）': '- {server}.{tool} ({caps}, {n} calls)',
  '未分类': 'uncategorised',
  '## 已从基线移除（潜在 − 实际）：{n}': '## Removed from the baseline (potential − observed): {n}',
  '- {server}.{tool}（{caps}）': '- {server}.{tool} ({caps})',
  '- … 还有 {n} 条': '- … {n} more',
  'invalid day: {day}（期望 YYYY-MM-DD）': 'invalid day: {day} (expected YYYY-MM-DD)',
  '✅ H4 达成：连续使用已满窗口': '✅ H4 reached: active for a full window',
  '⏳ 进行中': '⏳ in progress',
  '❌ 已中断': '❌ broken',
  'H4 留存（窗口 {window} 天，今天 {today}）': 'H4 retention (window {window} days, today {today})',
  '- 结论：{verdict}': '- Verdict: {verdict}',
  '- 连续活跃：{n} 天': '- Active streak: {n} days',
  '- 窗口内活跃：{active}/{window} 天（缺 {missing} 天）':
    '- Active days in window: {active}/{window} ({missing} missing)',
  '- 上次使用：{last}': '- Last used: {last}',
  '无记录': 'no record',

  // ── sync / onboard / snapshot / notify 与零散包内错误 ──
  '未找到云配置 {path}（先 pod cloud-setup 或手工写入 api_url/agent_id/sync_token）':
    'Cloud config {path} not found (run pod cloud-setup first, or write api_url/agent_id/sync_token by hand)',
  '云配置 {path} 缺少 api_url': 'Cloud config {path} is missing api_url',
  '云配置 {path} 的 agents 条目缺少 local_agent/agent_id/sync_token':
    'An agents entry in cloud config {path} is missing local_agent/agent_id/sync_token',
  '云配置 {path} 缺少 agent_id/sync_token（或 agents 数组）':
    'Cloud config {path} is missing agent_id/sync_token (or the agents array)',
  '服务端拒绝（哈希链断裂，server={server}）：{detail}':
    'Server refused (broken hash chain, server={server}): {detail}',
  '同步失败 HTTP {status}：{detail}': 'Sync failed with HTTP {status}: {detail}',
  '拉取策略失败 HTTP {status}：{detail}': 'Pulling policies failed with HTTP {status}: {detail}',
  '策略 "{name}" 签名无效（可能被篡改），已拒绝写入':
    'Policy "{name}" has an invalid signature (possibly tampered with); refusing to write it',
  '策略 "{name}" 带签名但未配置 policy_public_key，无法验签':
    'Policy "{name}" is signed but policy_public_key is not configured, so it cannot be verified',
  '策略 "{name}" 缺少签名（--require-signature）': 'Policy "{name}" has no signature (--require-signature)',
  '；从链首重推仍未通过：{error}': '; replaying from the chain head still failed: {error}',
  'sync token 无效（HTTP 401）': 'sync token is invalid (HTTP 401)',
  '{path}（超过 {max} 个条目上限）': '{path} (over the {max}-entry limit)',
  '{path}（不可读）': '{path} (unreadable)',
  '{path}（{size} bytes 超过剩余配额 {quota}）': '{path} ({size} bytes exceeds the remaining quota of {quota})',
  'pod 需要审批': 'pod needs your approval',
  '无法解析 {path}：{error}': 'Could not parse {path}: {error}',
  '{path} → "{name}" (已由 pod 包装)': '{path} → "{name}" (already wrapped by pod)',
  '{path} → "{name}" (transport={transport}，v0 只支持 stdio)':
    '{path} → "{name}" (transport={transport}; v0 supports stdio only)',
  '令牌不是合法 JSON': 'Token is not valid JSON',

  // ── 策略求值与 lint（packages/policy）──
  'source.command 不匹配：策略要求 "{expected}"，实际 "{actual}"':
    'source.command mismatch: the policy requires "{expected}" but the actual command is "{actual}"',
  'source.package 要求 "{expected}"，但启动命令不是 npx 来源':
    'source.package requires "{expected}", but the launch command is not an npx source',
  'source.package 不匹配：策略要求 "{expected}"，实际 "{actual}"':
    'source.package mismatch: the policy requires "{expected}" but the actual package is "{actual}"',
  'source.version 不匹配：策略要求 "{expected}"，实际 "{actual}"':
    'source.version mismatch: the policy requires "{expected}" but the actual version is "{actual}"',
  '(未锁定)': '(unpinned)',
  'defaultDecision="{value}" 是 fail-open，未登记 server 将被放行（建议 deny）':
    'defaultDecision="{value}" is fail-open: unregistered servers will be allowed (deny is recommended)',
  '未配置任何 server 规则（空策略）': 'No server rules configured (empty policy)',
  '未声明 server 来源白名单（建议声明 command 或 npm package，见 T4）':
    'No server source allowlist declared (declare command or npm package; see T4)',
  'deny 为空数组（无实际拒绝规则）': 'deny is an empty array (no actual deny rules)',
  'allow 含 "*"（该 server 全部工具放行；建议最小授权）':
    'allow contains "*" (every tool on that server is allowed; prefer least privilege)',
  '未配置 secrets 规则（建议加 deny_input_paths 与 deny_output_matching，见 T2）':
    'No secrets rules configured (add deny_input_paths and deny_output_matching; see T2)',
  '"{pattern}" 的前缀会被归一化，按路径段匹配任意位置；若只想限制当前用户目录，请写绝对路径':
    '"{pattern}" has its prefix normalised, so it matches that path segment anywhere; if you only mean the current user directory, write an absolute path',
  '非法正则: {pattern}': 'Invalid regex: {pattern}',
  '未启用输出侧熵检测（建议 enabled=true，兜底未知格式密钥，见 T2）':
    'Output-side entropy detection is off (consider enabled=true as a backstop for unknown key formats; see T2)',
  'threshold={value} 偏低，可能误伤正常文本（建议 ≥4.0）':
    'threshold={value} is low and may flag normal text (4.0 or higher is recommended)',
  '未知能力标签 "{capability}"（不会生效）': 'Unknown capability label "{capability}" (it has no effect)',
  '未知能力标签 "{capability}"': 'Unknown capability label "{capability}"',
  '配置了 capabilityRules 但没有 capabilityMap/capabilities，规则不会命中任何工具；先运行 pod graph apply':
    'capabilityRules is configured but there is no capabilityMap/capabilities, so no tool will ever match; run pod graph apply first',
  'capabilityRules.allow 是放宽规则（未在 servers 显式登记的工具会按能力放行）；请确保 capabilityMap 覆盖准确':
    'capabilityRules.allow loosens things (tools not explicitly listed under servers are allowed by capability); make sure the capabilityMap is accurate',

  // ── 身份与委托校验（packages/identity）──
  '非法 agent 名: {agent}（只允许 A-Za-z0-9._-）':
    'Invalid agent name: {agent} (only A-Za-z0-9._- are allowed)',
  'agent "{agent}" 没有私钥（先跑 pod identity init --agent {agent}）':
    'Agent "{agent}" has no private key (run pod identity init --agent {agent} first)',
  '委托必须由 parent 自己签名：parent={parent} signer={signer}':
    'A delegation must be signed by the parent itself: parent={parent} signer={signer}',
  '找不到 {agent} 的公钥': 'Public key for {agent} not found',
  '{parent} → {child} 的签名不成立': 'Signature for {parent} → {child} does not verify',
  '深度字段与实际链长不符：depth={depth} chain={chain}':
    'Depth field does not match the actual chain length: depth={depth} chain={chain}',
  '委托深度 {depth} 超过上限 {max}': 'Delegation depth {depth} exceeds the limit of {max}',
  '本跳委托已过期（{ts}）': 'This delegation hop has expired ({ts})',
  '找不到 {agent} 的公钥（链第 {i} 跳）': 'Public key for {agent} not found (hop {i} of the chain)',
  '{parent} → {child} 的签名不成立（链第 {i} 跳）':
    'Signature for {parent} → {child} does not verify (hop {i} of the chain)',
  '{parent} → {child} 已过期（链第 {i} 跳）': '{parent} → {child} has expired (hop {i} of the chain)',
  '{parent} → {child} 扩大了权限（父 {prevParent}→{prevChild} 没有：{escaped}）':
    '{parent} → {child} widened its capabilities (the parent {prevParent}→{prevChild} did not have: {escaped})',
  '{parent} → {child} 下放了不可委托的能力：{bad}':
    '{parent} → {child} delegated capabilities that cannot be delegated: {bad}',
  '找不到签发者 {issuer} 的公钥': 'Public key for issuer {issuer} not found',
  '令牌签名不成立': 'Token signature does not verify',
  '令牌已过期（{ts}）': 'Token has expired ({ts})',
  '令牌是单次使用，已经在 {ts} 被消费': 'Token is single-use and was already consumed at {ts}',

  // ── redteam / llm / observe / 网关来源校验 / 策略草稿 ──
  '策略文件不存在：{path}': 'Policy file not found: {path}',
  '策略文件不是合法 JSON：{path}（{error}）': 'Policy file is not valid JSON: {path} ({error})',
  '场景文件 {path}：接收 {accepted} 条，丢弃 {rejected} 条。':
    'Scenario file {path}: {accepted} accepted, {rejected} rejected.',
  '权限面已导出：{path}（这是唯一需要交给模型的东西）':
    'Capability surface exported: {path} (the only thing handed to the model)',
  '⚠️ 模型调用未能写入审计链：{error}':
    '⚠️ The model call could not be written to the audit chain: {error}',
  '空内容': 'Empty content',
  '审计目录 {dir} 在给定时间窗内没有记录': 'Audit directory {dir} has no records in the given window',
  'server "{name}" 未通过来源白名单校验（T4）：{detail}':
    'server "{name}" failed the source allowlist check (T4): {detail}',
  '审计目录为空或没有匹配记录，无法生成草稿':
    'The audit directory is empty or has no matching records; cannot build a draft',
  '草稿基于 {n} 条录制记录；启用前请人工复核并运行 pod lint':
    'The draft is based on {n} recorded calls; review it by hand and run pod lint before enabling',
  'agent：{agent}　未登记 server 默认：{defaultDecision}':
    'agent: {agent}  unregistered-server default: {defaultDecision}',
  '（没有可用的录制记录）': '(no usable recorded calls)',
  '| server | tool | 调用 | ok | err | blocked | 敏感 | 建议 | 依据 |':
    '| server | tool | calls | ok | err | blocked | sensitive | suggestion | basis |',
  '## 复核要点': '## What to review',
  '- `allow` 只代表"录制期间只读/未命中高危动词"，不代表绝对安全；':
    '- `allow` only means "read-only or no high-risk verb during recording" — it is not proof of safety;',
  '- `approve` 是写/执行类，保留人工闸门；`deny` 是破坏性动作或观测到敏感命中；':
    '- `approve` covers writes and execution and keeps a human gate; `deny` covers destructive actions or observed sensitive hits;',
  '- 未在语料中出现的工具不会进策略，启用后按 `defaultDecision` 处理（fail-closed）。':
    '- Tools absent from the corpus never enter the policy; once enabled they follow `defaultDecision` (fail-closed).',
  '**下一步**：复核本报告 → `pod lint --policy <draft>` → `pod serve --policy <draft>`':
    '**Next step**: review this report → `pod lint --policy <draft>` → `pod serve --policy <draft>`',
  '（无差异）': '(no differences)',
  '> ⚠️ 有放宽项，启用前必须人工复核。':
    '> ⚠️ Some items loosen access; human review is required before enabling.',

  // ── pod harden 报告 ──
  '> 本报告由 pod 在本机生成，采集与计算全程不出机器。':
    '> This report was generated by pod on this machine; collection and analysis never left it.',
  '> 所有结论都可追溯到具体事实与规则版本；报告附件的 sha256 见 §10，可用 `pod harden --verify <目录>` 独立复验。':
    '> Every finding traces back to a concrete fact and a rules version; attachment sha256 hashes are in §10 and can be verified independently with `pod harden --verify <dir>`.',
  '交付对象': 'Prepared for',
  '出具方': 'Prepared by',
  '报告编号': 'Report ID',
  '生成时间': 'Generated at',
  '机器': 'Machine',
  '判定规则版本': 'Rules version',
  '## 0. 执行摘要': '## 0. Executive summary',
  '**结论**：本机扫出 {high} 条 high、{medium} 条 medium、{low} 条 low；agent 平台 {platforms} 个、MCP server {servers} 个、疑似暴露凭据 {secrets} 处；审计链 {chains} 条（{entries} 条记录），断裂 {broken} 条。':
    '**Verdict**: {high} high, {medium} medium, {low} low findings; {platforms} agent platforms, {servers} MCP servers, {secrets} exposed credentials; {chains} audit chains ({entries} entries) with {broken} broken.',
  '| 严重级别 | 数量 |': '| Severity | Count |',
  '**本次最重要的三件事**（完整待办见 §2）：': '**The three most important things this round** (full list in §2):',
  '⚠️ 尚未建立姿态基线：本次只能做静态判定，配置/记忆/钩子的**变更**类检查未生效——这是当前最大的可见性缺口（`pod posture freeze` 可消除）。':
    '⚠️ No posture baseline yet: this round is static-only, and **change** detection for configs, memory and hooks is inactive — the biggest visibility gap right now (`pod posture freeze` closes it).',
  '覆盖声明：有确定性判定 {automated} 类 · 只能给信号 {partial} 类 · pod 看不到 {gap} 类。':
    'Coverage: {automated} with deterministic detection · {partial} signal-only · {gap} invisible to pod.',
  '## 1. 范围与方法': '## 1. Scope and method',
  '这次审计读了什么：本机（{home}）上各个 agent harness 的配置文件、项目级 MCP 配置、生命周期钩子、长期记忆文件与 MCP server 启动命令。':
    'What this audit read: the config files of every agent harness on this machine ({home}), project-level MCP configs, lifecycle hooks, long-term memory files and MCP server launch commands.',
  '怎么得出结论的：只读采集事实 → 按你的规则版本（{version}）做确定性判定 → 从真实调用语料编译最小权限策略 → 对审计链做完整性校验。全程不联网、不上传、不修改被审计的配置。':
    'How the conclusions were reached: read-only fact collection → deterministic decisions under your rules version ({version}) → least-privilege policy compiled from the real tool-call corpus → integrity check of the audit chains. No network, no uploads, no modification of audited configs.',
  '本报告的边界（先读这一段再看结论）：': 'The boundaries of this report (read this before the findings):',
  '- 这是**某个时点**的快照。没有建立姿态基线时，配置/钩子/记忆的变更类判定不生效。':
    '- This is a snapshot at one point in time. Without a posture baseline, change detection for configs, hooks and memory is inactive.',
  '- 没有真实调用语料时，§7 的策略只是从静态事实推断的草稿，不是最小权限。':
    '- Without a real tool-call corpus, the policy in §7 is a draft inferred from static facts, not least privilege.',
  '- pod 不做沙箱隔离，也看不到 harness 进程内部的推理与对话；§3 写清了看不到的那部分。':
    '- pod does not sandbox, and cannot see reasoning or conversations inside the harness; §3 spells out what is out of sight.',
  '复现这次审计：': 'Reproduce this audit:',
  'pod harden --out <目录>          # 重跑一次，产出与本次同构的报告':
    'pod harden --out <dir>          # re-run; produces a report of the same shape',
  'pod harden --verify <目录>       # 校验已交付的报告包有没有被改动':
    'pod harden --verify <dir>       # check whether a delivered package was modified',
  '## 2. 结论与待办': '## 2. Findings and next steps',
  '本轮没有可判定的问题。**这不等于"安全"**——§3 列了 pod 看不到的部分。':
    'No decidable findings this round. **That is not the same as "secure"** — §3 lists what pod cannot see.',
  '按严重级别排序，共 {total} 条；先处理以下 {n} 条：': 'Sorted by severity; {total} findings — start with these {n}:',
  '| 级别 | 来源 | 类别 | 问题 | 位置 |': '| Severity | Source | Category | Issue | Where |',
  '（其余 {n} 项见 `findings.json`）': '({n} more in `findings.json`)',
  '### 待办（命令可直接复制）': '### To-do (commands are copy-paste ready)',
  '确认：`{cmd}`{residual}': 'Check: `{cmd}`{residual}',
  '（pod 只能发现/降低风险，做完不会消失）': ' (pod can only detect or reduce risk; this will not disappear)',
  '### 建议的执行顺序': '### Suggested order of work',
  'pod identity init --agent <agent>   # 1. 每个 agent 一个身份':
    'pod identity init --agent <agent>   # 1. one identity per agent',
  'pod posture freeze                  # 2. 冻结当前姿态（此后任何变更都会报出来）':
    'pod posture freeze                  # 2. freeze the current posture (any later change gets reported)',
  '  --policy <draft> --policy-signature <sig>   # 3. 用编译出的最小权限策略接管流量':
    '  --policy <draft> --policy-signature <sig>   # 3. put the compiled least-privilege policy in front of traffic',
  'pod posture --strict                # 4. 挂进 CI / 定时任务，漂移即退出码非 0':
    'pod posture --strict                # 4. wire into CI / a cron job; drift exits non-zero',
  'pod rules pull --url <pack> --key <pub.pem>   # 5. 订阅规则更新（放宽守卫默认拦截）':
    'pod rules pull --url <pack> --key <pub.pem>   # 5. subscribe to rule updates (the loosening guard blocks by default)',
  'pod quarantine add --agent <agent>  # 出事时熔断，网关下一次调用即生效':
    'pod quarantine add --agent <agent>  # quarantine when things go wrong; takes effect on the next gateway call',
  '## 3. 覆盖边界（本报告不能证明什么）': '## 3. Coverage boundaries (what this report cannot prove)',
  '威胁目录共 {total} 类：有确定性判定 {automated} 类、只能给信号 {partial} 类、pod 看不到 {gap} 类。本机触发到的部分见 §5 的覆盖边界小节。':
    'The threat catalog has {total} entries: {automated} with deterministic detection, {partial} signal-only, {gap} invisible to pod. See the coverage subsection in §5 for what fired on this machine.',
  '- **不能替代沙箱**：pod 在工具边界与配置层做判定，不做进程隔离。':
    '- **Not a sandbox**: pod decides at the tool boundary and the config layer; it does not isolate processes.',
  '- **看不到 harness 进程内部**：钩子在 harness 里直接执行、项目级配置自动加载、`--dangerously-skip-permissions` 这类开关，pod 能发现与取证，拦不住。':
    '- **Cannot see inside the harness process**: hooks run inside the harness, project-level configs auto-load, and flags like `--dangerously-skip-permissions` are detectable and provable but not blockable.',
  '- **不校验包签名与发布者**：版本锁定只回答"装的是哪一版"。':
    '- **No package signing or publisher checks**: version pinning only answers "which version is installed".',
  '- **没有审计链就没有历史**：本机的审计链状态见 §8；链为空时，"它做过什么"无法证明。':
    '- **No chain, no history**: see §8 for this machine\'s audit chains; when they are empty, there is no way to prove what ran.',
  '## 4. 暴露面（静态扫描）': '## 4. Exposure (static scan)',
  '## 5. 多 agent / 多 harness 覆盖面': '## 5. Multi-agent / multi-harness coverage',
  '扫描了 {harnesses} 类 harness（{installed} 类已安装）、{servers} 个 MCP server、{hooks} 个钩子、{projects} 个工作区；其中未纳管的 harness {unmanaged} 个。':
    'Scanned {harnesses} harness types ({installed} installed), {servers} MCP servers, {hooks} hooks and {projects} workspaces; {unmanaged} installed harnesses are unmanaged.',
  '## 6. 控制平面姿态': '## 6. Control-plane posture',
  '## 7. 最小权限策略建议': '## 7. Least-privilege policy suggestions',
  '审计目录为空，无法从真实行为编译最小权限策略。':
    'The audit directory is empty, so no least-privilege policy can be compiled from real behaviour.',
  '先采集语料：`pod record --config <mcp-manager.json> --server <name>`，':
    'Collect a corpus first: `pod record --config <mcp-manager.json> --server <name>`,',
  '日常使用一段时间后再跑 `pod harden`——**没有语料的策略只是猜测**。':
    'then run `pod harden` after a while of normal use — **a policy without a corpus is just a guess**.',
  '## 8. 证据与可验证性': '## 8. Evidence and verifiability',
  '## 9. 如何验证这份交付物': '## 9. How to verify this deliverable',
  '这份报告不需要你信任 pod 或它的运营者——三条命令都能独立复验：':
    'This report asks you to trust neither pod nor its operator — three commands verify it independently:',
  'pod harden --verify <报告目录>        # 逐文件重算 sha256，比对 manifest.json':
    'pod harden --verify <report dir>        # recompute sha256 per file and compare with manifest.json',
  'pod verify-evidence <报告目录>/evidence.json   # 校验证据包本身（如有）':
    'pod verify-evidence <report dir>/evidence.json   # verify the evidence bundle itself (if present)',
  'sha256sum <报告目录>/*   # 与 manifest.json 里记录的 sha256 逐一比对':
    'sha256sum <report dir>/*   # compare each value with the sha256 recorded in manifest.json',
  '任何一份产物被改动一个字节，第一步就会失败并指出是哪个文件。':
    'A single changed byte in any artifact makes the first command fail and name the file.',
  '## 10. 产物清单与交付声明': '## 10. Files produced and delivery statement',
  '| 文件 | 字节 | sha256 |': '| File | Bytes | sha256 |',
  '完整哈希见 `manifest.json`；`manifest.json` 本身不进清单（否则会自我引用）。':
    'Full hashes are in `manifest.json`; `manifest.json` itself is not listed (that would be self-referential).',
  '**声明**：本报告由 pod 在 {home} 于 {ts} 生成，生成后未被修改；采集与判定全程未离开该机器；报告中的凭据只保留掩码，不含任何密钥原文。':
    '**Statement**: this report was generated by pod on {home} at {ts} and has not been modified since; collection and decision-making never left that machine; credentials appear only as masks, never in plaintext.',
  '  harness 扫描 {harnesses} 类（{installed} 类已安装，{unmanaged} 类未纳管）· 真实调用语料 {corpus} 条':
    '  harnesses scanned: {harnesses} ({installed} installed, {unmanaged} unmanaged) · real tool-call corpus: {corpus} entries',
  '找不到 {path}——这不是一份 pod harden 交付目录':
    'Not found: {path} — this is not a pod harden deliverable directory',
  'manifest.json 解析失败：{reason}': 'Failed to parse manifest.json: {reason}',
  '✅ 交付物校验通过：{n} 份产物哈希全部匹配（生成于 {ts}）':
    '✅ Deliverable verified: all {n} artifact hashes match (generated at {ts})',
  '❌ 交付物校验失败：缺失 {missing} 份、哈希不匹配 {mismatch} 份':
    '❌ Deliverable verification failed: {missing} missing, {mismatch} hash mismatch(es)',
  '   - 缺失：{file}': '   - missing: {file}',
  '   - 已被修改：{file}': '   - modified: {file}',
  '     期望 {expected}': '     expected {expected}',
  '     实际 {actual}': '     actual   {actual}',

  // ── 规则包应用/签名/拉取与云端熔断下发（index.ts）──
  '规则包 {version}（{issuer}）已应用 → {target}':
    'Rule pack {version} ({issuer}) applied → {target}',
  '  收紧 {tightened} 项 · 放宽 {relaxed} 项 · 方向待人工确认 {unknown} 项':
    '  {tightened} tightened · {relaxed} loosened · {unknown} need a human call on direction',
  '  ⚠️ 放宽：{where}（{kind}{detail}）': '  ⚠️ Loosened: {where} ({kind}{detail})',
  '⚠️ 规则已应用，但未能写入审计链：{error}':
    '⚠️ The rules were applied, but could not be written to the audit chain: {error}',
  'pod onboard — 计划（dry-run，未修改任何文件）': 'pod onboard — plan (dry-run, nothing was modified)',
  'pod onboard — 已接管': 'pod onboard — taken over',
  '⛔ 云端下发熔断并已在本地生效（agent #{id}）：{list}':
    '⛔ Cloud quarantine published and already in effect locally (agent #{id}): {list}',
  '✅ 云端解除熔断（agent #{id}）：{list}': '✅ Cloud quarantine lifted (agent #{id}): {list}',
  '⛔ 本地已处于熔断状态（agent #{id}）': '⛔ Already quarantined locally (agent #{id})',
  '⚠️ agent #{id} 熔断状态未同步：{error}': '⚠️ Quarantine state for agent #{id} was not synced: {error}',
  '加固审计报告已生成：{path}': 'Hardening audit report generated: {path}',
  '  agent 平台 {platforms} · MCP server {servers} · 疑似暴露密钥 {secrets}':
    '  agent platforms {platforms} · MCP servers {servers} · suspected exposed secrets {secrets}',
  '  ⚠️ 未建立姿态基线：漂移类检查未生效，建议先跑 pod posture freeze':
    '  ⚠️ No posture baseline yet: drift checks are inactive — run pod posture freeze first',
  '  交付目录：{path}': '  Deliverable directory: {path}',
  '云配置里没有 sync_token，无法上传（{config}）':
    'No sync_token in the cloud config, so nothing can be uploaded ({config})',
  '已上传到云端（报告 #{id}）：report.md + findings.json':
    'Uploaded to the cloud (report #{id}): report.md + findings.json',
  '  未上传：evidence.json（原始审计链）——它在本地目录里，需要时你自己决定要不要给。':
    '  Not uploaded: evidence.json (the raw audit chain) — it stays in the local directory; you decide whether to share it.',
  '红队报告已写入：{path}': 'Red-team report written to: {path}',
  'redteam 失败：{error}': 'redteam failed: {error}',
  '签名已写入: {path}': 'Signature written to: {path}',
  '判定规则：{path}': 'Rules: {path}',
  '（尚未创建，当前使用代码内置默认值）': '(not created yet — using the built-in defaults)',
  '  egress 判定：{state}': '  egress verdict: {state}',
  '开启': 'on',
  '关闭（默认）': 'off (default)',
  '规则包已签名并写入：{path}': 'Rule pack signed and written to: {path}',
  '✅ 签名有效（{issuer} · {version} · {at}）': '✅ Signature valid ({issuer} · {version} · {at})',
  '云配置里没有 sync_token，无法拉取规则包（{config}）':
    'No sync_token in the cloud config, so the rule pack cannot be pulled ({config})',
  '规则包拉取失败：HTTP {status} {url}\n{detail}': 'Pulling the rule pack failed: HTTP {status} {url}\n{detail}',
  '云端响应里没有 pack_json（服务端版本可能过旧）':
    'The cloud response has no pack_json (the server may be too old)',
  '云端当前生效版本：{version} {note}': 'Active version in the cloud: {version} {note}',
  '规则包验签失败——拒绝应用（包内容与签名不匹配，或公钥不对）':
    'Rule pack signature verification failed — refusing to apply it (contents do not match the signature, or the public key is wrong)',
  '⚠️ 未提供 --key：跳过验签。本地文件适用，但无法证明这个包确实来自签发方。':
    '⚠️ No --key given: skipping signature verification. Fine for local files, but it cannot prove the pack really came from the issuer.',
  '# pod 加固审计报告': '# pod hardening audit report',
  '✅ 已建立姿态基线：配置、记忆、钩子、包来源的漂移检查均已生效。':
    '✅ Posture baseline in place: drift checks on config, memory, hooks and package sources are all active.',
  '（审计目录为空，未导出证据包——**没有记录就没有可证明的历史**）':
    '(the audit directory is empty, so no evidence bundle was exported — **no records means no provable history**)',
  '# 审计完整性自检\n\n（审计目录为空）': '# Audit integrity self-check\n\n(the audit directory is empty)',
  '  审计链 {chains} 条 / {entries} 条记录{broken}': '  {chains} audit chains / {entries} records{broken}',
  '（⚠️ {n} 条断裂）': ' (⚠️ {n} broken)',

  // ── guard（多 agent / 多 harness 持续漏洞扫描）──
  '# pod guard — 多 agent / 多 harness 漏洞扫描': '# pod guard — multi-agent / multi-harness vulnerability scan',
  '> 只读扫描：不联网、不上传、不修改任何文件。判定规则来自你的 rules.json。':
    '> Read-only scan: no network, no uploads, no file changes. The verdict rules come from your rules.json.',
  '机器：{home}': 'Machine: {home}',
  '## 0. 概览': '## 0. Overview',
  '扫描范围：{harnesses} 个 harness（{installed} 个已安装）、{servers} 个 MCP server、{hooks} 个钩子、{secrets} 处明文凭据、{projects} 个工作区。':
    'Scanned: {harnesses} harnesses ({installed} installed), {servers} MCP servers, {hooks} hooks, {secrets} plaintext credentials, {projects} workspaces.',
  '覆盖声明：{automated} 类有确定性判定、{partial} 类只能给信号、{gap} 类 pod 看不到（见 §4）。':
    'Coverage: {automated} categories are decided deterministically, {partial} can only raise a signal, {gap} are invisible to pod (see §4).',
  '本轮没有发现可判定的问题。注意这不等于"安全"——§4 列了 pod 看不到的那部分。':
    'No decidable problems this round. That is not the same as "safe" — §4 lists what pod cannot see.',
  '### 先做这三件事': '### Do these three things first',
  '没有需要立刻处理的项（这不等于"没问题"，见 §4 的覆盖边界）。':
    'Nothing needs immediate action (that is not the same as "no problems" — see the coverage boundaries in §4).',
  '   确认：`{cmd}`': '   Check: `{cmd}`',
  '   覆盖：pod 只能发现或降低风险，处理完这类问题**不会**消失——原因见 §4。':
    '   Coverage: pod can only detect or reduce risk here; fixing it will **not** make this class of finding disappear — see §4.',
  '   覆盖：pod 有执行点，处理完这类问题就消失了。':
    '   Coverage: pod has an enforcement point here; once fixed, this class of finding disappears.',
  '### 从扫描到交付': '### From scan to deliverable',
  '本轮扫出 {total} 条：可根治 {fixable} · 只能降险/发现 {review} · pod 看不到 {uncovered}。':
    'This round found {total}: {fixable} fixable · {review} risk-reduction/detection only · {uncovered} invisible to pod.',
  '报告目录里包含：': 'The report directory contains:',
  '扫描回答"现在有什么问题"；要把同一批事实变成一份能交给客户/审计方、并且对方自己就能校验的报告，用 pod harden。':
    'The scan answers "what is wrong right now"; to turn the same facts into a report you can hand to a client or auditor — one they can verify themselves — use pod harden.',
  '执行摘要与扫描范围（哪些看到了、哪些没看到）':
    'Executive summary and scan scope (what was seen, what was not)',
  '按优先级排序的待办，每条带可执行命令':
    'A prioritized to-do list where every item comes with a runnable command',
  '从真实调用编译的最小权限策略草稿':
    'A least-privilege policy draft compiled from real tool calls',
  '证据包 + 逐文件 sha256 清单（对方用 pod harden --verify 独立复验）':
    'An evidence bundle plus a per-file sha256 manifest (the recipient verifies it with pod harden --verify)',
  '## 1. 漏洞清单': '## 1. Vulnerability list',
  '（空）': '(empty)',
  '（其余 {n} 处见 guard-findings.json）': '({n} more in guard-findings.json)',
  '## 2. 建议清单（按优先级）': '## 2. Recommendations (by priority)',
  '（没有需要处理的项）': '(nothing to act on)',
  '对应威胁：`{threat}`{title} · 影响 {count} · harness：{affects}':
    'Threat: `{threat}`{title} · affects {count} · harness: {affects}',
  '为什么：{why}': 'Why: {why}',
  'pod 覆盖：有确定性判定 + 有执行点——处理完这类问题就消失了。':
    'pod coverage: deterministic detection plus an enforcement point — fixing it removes this class of problem.',
  'pod 覆盖：能发现，但拦不住（缺口见 §4）。':
    'pod coverage: detectable, but not blockable (see the gap in §4).',
  'pod 覆盖：pod 看不到这类问题，只能靠人工与外部工具。':
    'pod coverage: invisible to pod; only manual work and external tooling can help.',
  '可以让模型生成加固建议物：`pod guard remediate --llm`（建议物不自动生效，先过放宽守卫）。':
    'A model can draft remediation proposals: `pod guard remediate --llm` (proposals never auto-apply; they pass the relaxation guard first).',
  '确认：`{cmd}`': 'Check: `{cmd}`',
  '这一条不能根治：pod 只能发现或降低风险，剩余风险见 §4。':
    'This one is not fully fixable: pod can only detect or reduce the risk; residual risk is in §4.',
  '## 3. 让扫描持续跑起来': '## 3. Keep the scan running',
  'pod guard baseline            # 把当前状态冻结为基线（此后只对新增/变化报警）':
    'pod guard baseline            # freeze the current state as a baseline (only changes alert afterwards)',
  'pod guard watch --interval 300  # 每 5 分钟扫一轮，有变化就写进审计链':
    'pod guard watch --interval 300  # scan every 5 minutes; changes go into the audit chain',
  'pod guard scan --strict       # high 时退出码 1，可直接挂 CI / 定时任务':
    'pod guard scan --strict       # exit code 1 on high severity, ready for CI or cron',
  '## 4. 覆盖边界与出处': '## 4. Coverage boundaries and sources',
  '**能发现但拦不住（缺口必须说清楚）**': '**Detectable but not blockable (gaps must be spelled out)**',
  '**pod 看不到的**': '**Invisible to pod**',
  '**触发到的威胁与出处**': '**Threats triggered, with sources**',
  '（本轮没有触发任何目录条目）': '(no catalog entry was triggered this round)',
  '**采集说明**': '**Collection notes**',
  'pod guard 只读、不联网、不上传任何数据。': 'pod guard is read-only, offline, and uploads nothing.',
  '# pod guard 威胁目录': '# pod guard threat catalog',
  '> 每条都对应一个可自动执行的检测器，并带上可核查的外部出处。':
    '> Every entry maps to an executable detector and cites verifiable external sources.',
  '| 编号 | 严重级别 | 类别 | 覆盖 | 标题 |': '| ID | Severity | Category | Coverage | Title |',
  'OWASP：{asi} · 威胁模型：{local} · pod 覆盖：{coverage}':
    'OWASP: {asi} · threat model: {local} · pod coverage: {coverage}',
  '已有防线：': 'Existing controls:',
  '缺口：{gap}': 'Gap: {gap}',
  '建议：{action}': 'Recommended: {action}',
  '理由：{why}': 'Rationale: {why}',
  '出处：': 'Sources:',
  '凭据暴露': 'credential exposure',
  '代码执行': 'code execution',
  '边界与闸门': 'boundary and gates',
  '网络暴露': 'network exposure',
  '供应链': 'supply chain',
  '权限与审批': 'permissions and approval',
  '记忆完整性': 'memory integrity',
  '身份与归因': 'identity and attribution',
  '可见性与证据': 'visibility and evidence',
  'guard 报告已写入：{path}': 'guard report written to: {path}',
  '  机器可读清单：{path}': '  machine-readable findings: {path}',
  'guard 基线已写入 {path}': 'guard baseline written to {path}',
  '  冻结 {servers} 个 MCP server 指纹 · {hooks} 个钩子指纹':
    '  froze {servers} MCP server fingerprints · {hooks} hook fingerprints',
  '  之后同名 server 换包/改参数会在 pod guard scan 里报出来（需 rules.packages.requireIntegrity=true）':
    '  from now on a renamed package or changed args for the same server shows up in pod guard scan (needs rules.packages.requireIntegrity=true)',
  '[{ts}] 无变化（{total} 条已知问题）': '[{ts}] no change ({total} known findings)',
  '[{ts}] 新增 {added} · 变化 {changed} · 消失 {resolved}（共 {total} 条）':
    '[{ts}] new {added} · changed {changed} · gone {resolved} ({total} total)',
  'guard watch 结束：{rounds} 轮 · 新增 {added} · 变化 {changed} · 消失 {resolved}':
    'guard watch finished: {rounds} rounds · new {added} · changed {changed} · gone {resolved}',
  '--interval 必须是正数（秒），收到 {value}': '--interval must be a positive number of seconds, got {value}',
  '未知的 guard 子命令：{sub}（可用：scan / watch / remediate / baseline / catalog）':
    'Unknown guard subcommand: {sub} (available: scan / watch / remediate / baseline / catalog)',
  '出网上下文已导出：{path}（这是唯一需要交给模型的东西）':
    'Outbound context exported to {path} (this is the only thing a model needs to see)',
  '模型：{provider}/{model}': 'Model: {provider}/{model}',
  '本轮没有扫出需要处置的问题。': 'This round found nothing that needs remediation.',
  '没有发现可处置的问题，未调用模型（不为了"用上模型"而发数据出去）。':
    'Nothing actionable, so no model call was made (we do not send data out just to use a model).',
  '规则增量会放宽 {n} 处现有防线，已整体拒绝应用（与 pod rules apply 的放宽守卫同一口径）。':
    'The rule delta would relax {n} existing control(s), so the whole delta was refused (same relaxation guard as pod rules apply).',
  '没有可应用的规则增量（未生成，或被放宽守卫拒绝），rules.json 保持不变。':
    'No applicable rule delta (none produced, or refused by the relaxation guard); rules.json is unchanged.',
  '规则已应用到 {path}（原文件已备份为 rules.json.bak）':
    'Rules applied to {path} (the previous file was backed up as rules.json.bak)',
  '加固建议已写入：{path}': 'Remediation guidance written to: {path}',
  '# pod guard — 加固建议（模型辅助）': '# pod guard — remediation guidance (model-assisted)',
  '> 建议物不自动生效。规则增量必须过放宽守卫（与 pod rules apply 同一套判定）。':
    '> Proposals never auto-apply. Rule deltas must pass the relaxation guard (the same check pod rules apply uses).',
  '## 结论': '## Conclusion',
  '## 处置步骤': '## Remediation steps',
  '（没有可用步骤——模型未产出，或产出全部被校验器丢弃）':
    '(no usable steps — the model produced none, or every item was dropped by the validator)',
  '## 规则增量': '## Rule delta',
  '增量已通过放宽守卫。写入 `rules-suggested.json`（增量）与 `rules-merged.json`（合并结果）。':
    'The delta passed the relaxation guard. Written to `rules-suggested.json` (the delta) and `rules-merged.json` (merged result).',
  '应用：`pod guard remediate --llm --apply`，或 `pod rules apply` 走签名包通道。':
    'Apply with `pod guard remediate --llm --apply`, or go through the signed-pack path with `pod rules apply`.',
  '**被放宽守卫拒绝**——这份增量会削弱现有防线，不应用：':
    '**Refused by the relaxation guard** — this delta would weaken existing controls, so it is not applied:',
  '（本次没有规则增量）': '(no rule delta this time)',
  '## 被丢弃的模型产出': '## Model output that was dropped',
  '## 参考：本轮扫描结论': '## Reference: this round’s scan result',
  '{high} high · {medium} medium · {low} low（完整清单见 guard-report.md）':
    '{high} high · {medium} medium · {low} low (full list in guard-report.md)',
  '这个 agent 名无法映射到身份目录（{error}）——先改名，再 pod identity init':
    'This agent name cannot map to an identity directory ({error}) — rename it first, then run pod identity init',
  '未加 --llm：本次只做本地扫描与产物落盘。处置步骤来自 `pod guard scan` 的建议清单；加 --llm 才会生成模型建议物。':
    'No --llm given: this run only scans locally and writes artifacts. Remediation steps come from the `pod guard scan` recommendations; pass --llm to have a model draft proposals.',

  // ── 纳管（pod agents / 控制台的「加入监控」）──
  '非法 agent 名：{agent}（只允许 A-Za-z0-9._-，长度 1-64；名字会进路径与审计链）':
    'Invalid agent name: {agent} (A-Za-z0-9._- only, length 1-64; the name goes into paths and the audit chain)',
  '纳管只写 ~/.pod 下的产物，不改动 harness 的配置。':
    'Enrolling only writes artifacts under ~/.pod; it does not touch the harness configuration.',
  '该 harness 有 {total} 个 MCP server，其中 {behind} 个经过 pod 网关——纳管本身不会拦住其余 {rest} 个。':
    'This harness has {total} MCP servers, {behind} of which go through the pod gateway — enrolling alone will not block the other {rest}.',
  '新建的策略是零权限起点（未登记 server 一律拒绝），需要采集语料后编译最小权限策略。':
    'The new policy is a zero-permission starting point (unregistered servers are denied); collect a corpus and compile a least-privilege policy from it.',
  'pod onboard --yes    # 把该 harness 的 MCP server 包进网关；不改配置就只有记录、没有闸门':
    'pod onboard --yes    # wrap this harness’s MCP servers in the gateway; without it you get records but no gate',
  'pod record --agent {agent} --server <name>    # 先只录不拦，采集真实调用':
    'pod record --agent {agent} --server <name>    # record-only first, to collect real calls',
  'pod policy draft --agent {agent} --diff <baseline>    # 编译最小权限策略，复核后再切执法':
    'pod policy draft --agent {agent} --diff <baseline>    # compile a least-privilege policy, review it, then enforce',
  'pod guard scan --strict    # 随时看这个 agent 的漏洞清单':
    'pod guard scan --strict    # see this agent’s vulnerability list at any time',
  '台账里没有这个 agent 的纳管记录——可能是手动创建的，pod 不动它。':
    'No enrollment record for this agent — it was probably created by hand, and pod leaves it alone.',
  '策略文件 {file} 现在绑定的是别的 agent，未删除':
    'Policy file {file} is now bound to a different agent, so it was not deleted',
  '策略文件 {file} 不存在或无法解析，跳过删除':
    'Policy file {file} is missing or unparsable; skipping deletion',
  '保留 {file}：它不是纳管时创建的，不删用户自己的策略':
    'Keeping {file}: it was not created by enrolling, and pod does not delete your own policies',
  '身份与私钥保留（删掉就无法再证明历史上的调用是它做的）；要删用 --purge-identity。':
    'Identity and private key kept (deleting them makes past calls unattributable); use --purge-identity to remove them.',
  '规则文件无法解析，纳管扫描暂按默认规则进行：{error}':
    'The rules file cannot be parsed; the enrollment scan falls back to default rules: {error}',
  '本机 harness 扫描失败，纳管列表为空：{error}':
    'Local harness scan failed, so the enrollment list is empty: {error}',
  'pod ui listening on http://{host}:{port}（可写：纳管 / 移除）':
    'pod ui listening on http://{host}:{port} (writable: enroll / remove)',
  'pod 控制台（只读模式）已启动：{url}': 'pod console started in read-only mode: {url}',
  'pod 控制台已启动：{url}': 'pod console started: {url}',
  '写操作已开启（页面上的「加入监控 / 移除监控」）：只写 ~/.pod 下的身份、零权限策略与审计记录，每次都会进哈希链。要关掉用 --read-only。':
    'Writes are enabled (the "Enroll / Remove" buttons): they only write identity, a zero-permission policy and audit records under ~/.pod, and every one goes into the hash chain. Use --read-only to disable.',
  '本机已安装 {installed} 个 harness，其中 {managed} 个已纳管。':
    '{installed} harnesses installed on this machine, {managed} of them enrolled.',
  '  harness          已纳管   agent                 servers  执法/进网关  漏洞(h/m/l)':
    '  harness          enrolled  agent                 servers  enforced/wrapped  findings(h/m/l)',
  '未纳管：{list}': 'Not enrolled: {list}',
  '纳管一个：pod agents enroll --harness <id> [--agent <name>]':
    'To enroll one: pod agents enroll --harness <id> [--agent <name>]',
  'pod agents enroll 需要 --harness <id>（先用 pod agents scan 看有哪些）':
    'pod agents enroll needs --harness <id> (run pod agents scan to list them)',
  'agent {agent} 已在纳管中（本次无改动）': 'agent {agent} is already enrolled (no changes)',
  '已纳管 agent {agent}（身份 {fp} · 策略 {policy}）':
    'Enrolled agent {agent} (identity {fp} · policy {policy})',
  'pod agents forget 需要 --agent <name>': 'pod agents forget needs --agent <name>',
  '已移除纳管 {agent}（策略 {policy} · 身份 {identity}）':
    'Removed enrollment for {agent} (policy {policy} · identity {identity})',
  '{agent} 没有纳管记录': '{agent} has no enrollment record',
  // ── 接管（把 MCP server 包进网关）──
  '{file}：TOML 配置暂不支持自动改写（`pod onboard` 只写 JSON 形态的 mcpServers）':
    '{file}: TOML configs cannot be rewritten automatically yet (pod onboard only writes JSON mcpServers)',
  '{file}：没读到可改写的 server 列表（只认 JSON 的 mcpServers 或 servers 数组）':
    '{file}: no rewritable server list found (only JSON mcpServers or a servers array is recognised)',
  '{file} → {name}：已经指向 pod，跳过': '{file} → {name}: already points at pod, skipping',
  '{file} → {name}：transport={transport}，v0 只支持 stdio':
    '{file} → {name}: transport={transport}; v0 only supports stdio',
  '接管会把 MCP server 的启动命令改写为 `pod serve --record-only …`，**默认只录不拦**：先采几天语料，再用 pod policy draft 编译最小权限策略、复核后切执法。':
    'Takeover rewrites each MCP server’s command to `pod serve --record-only …`, which **records but does not block**: collect a corpus for a few days, compile a least-privilege policy with pod policy draft, then switch to enforcement.',
  '改写前会把原配置备份成 <配置>.pod-backup-<时间戳>；移除接管会从最近的备份还原。':
    'The original config is backed up as <config>.pod-backup-<timestamp>; reverting restores from the most recent backup.',
  '只改用户级配置，不动仓库里的项目级配置（.mcp.json / .cursor/mcp.json 等）。':
    'Only user-level configs are touched; project-level configs in repositories (.mcp.json, .cursor/mcp.json, …) are left alone.',
  '包装沿用你已有的策略 {file}（不新建 allow-all 模板）——即使哪天去掉 --record-only，行为也是 fail-closed 而不是全部放行。':
    'The wrapper reuses your existing policy {file} (no allow-all template is created) — so even if --record-only is dropped later, the behaviour is fail-closed rather than wide open.',
  '在 PATH 上找不到 `{bin}`：包装后的命令会启动失败，导致该 harness 的 MCP server 全部不可用。先安装 pod 或改用 --pod-bin <绝对路径>。':
    '`{bin}` is not on PATH: the wrapped commands would fail to start, taking every MCP server of this harness down with them. Install pod first, or pass --pod-bin <absolute path>.',
  '这个 harness 的配置格式暂不支持自动改写（见下方说明）；可以手动跑 pod onboard --config <路径> --yes。':
    'This harness’s config format cannot be rewritten automatically yet (see the notes below); run pod onboard --config <path> --yes by hand instead.',
  '没有需要接管的 server（可能都已经在网关后面）。':
    'No server needs taking over (they may all be behind the gateway already).',
  '接管计划不可执行': 'The takeover plan is not applicable',
  '已接管：这些 server 现在经过 pod 网关，**只录不拦**（enforced=false）。':
    'Taken over: these servers now go through the pod gateway, **recording but not blocking** (enforced=false).',
  '下一步：用几天后跑 `pod policy draft` 编译最小权限策略，复核后把包装参数里的 --record-only 去掉即切执法。':
    'Next: run `pod policy draft` after a few days to compile a least-privilege policy, then drop --record-only from the wrapper to enforce.',
  '台账里没有这个 agent 的接管记录；已按该 harness 的配置路径尝试从最近备份还原。':
    'No takeover record for this agent; restored from the most recent backup using this harness’s config paths.',
  '没有找到可还原的备份（可能已经还原过，或配置文件被移动了）。':
    'No restorable backup found (it may already have been reverted, or the config was moved).',
  '已从最近的备份还原。策略文件与审计记录保留——它们不是配置的一部分。':
    'Restored from the most recent backup. Policy files and audit records are kept — they are not part of the config.',
  '接管改写了配置：如果你之前跑过 pod posture freeze，之后会看到配置漂移告警——确认这次改写无误后重新 pod posture freeze 即可。':
    'Takeover rewrote the config: if you ran pod posture freeze before, you will now see a config-drift alert — re-run pod posture freeze once you have confirmed the rewrite.',
  '配置已被改写：跑一次 `pod posture freeze` 把新配置记进基线，否则姿态检查会把这次改写报成漂移。':
    'The config was rewritten: run `pod posture freeze` once to record it in the baseline, otherwise the posture check reports this rewrite as drift.',
  'pod agents onboard 需要 --harness <id>（先用 pod agents scan 看有哪些）':
    'pod agents onboard needs --harness <id> (run pod agents scan to list them)',
  '接管计划（dry-run；加 --yes 才真正改写配置）':
    'Takeover plan (dry-run; add --yes to actually rewrite the config)',
  '    {name}：{from}': '    {name}: {from}',
  '      → {to}': '      → {to}',
  '    备份：{path}': '    backup: {path}',
  '不可执行：{reason}': 'Not applicable: {reason}',
  '策略：{path}{reuse}': 'Policy: {path}{reuse}',
  '（沿用已有策略，不覆盖）': ' (reusing the existing policy, not overwriting it)',
  '已接管 {harness} → agent {agent}': 'Took over {harness} → agent {agent}',
  '  {config}：{servers}（备份 {backup}）': '  {config}: {servers} (backup {backup})',
  '接管失败：{error}': 'Takeover failed: {error}',
  'pod agents revert 需要 --agent <name>': 'pod agents revert needs --agent <name>',
  '已还原 {n} 个配置': 'Restored {n} config file(s)',

  // ── 切执法 / 回到只录不拦 ──
  '{name}：已经是只录不拦，跳过': '{name}: already recording only, skipping',
  '{name}：已经不在只录模式，跳过': '{name}: no longer in record-only mode, skipping',
  '回到只录不拦：策略不变，只是不再阻断——用来在执法打断工作流时快速退一步。':
    'Back to record-only: the policy is unchanged, it just stops blocking — useful when enforcement is getting in the way.',
  '切执法后，命中 approve 的调用会挂起等审批（超时按拒绝处理）。没在跑 `pod watch` 的话，它们会等到超时被拒——这是 fail-closed，不是故障。':
    'After switching to enforcement, calls that hit approve suspend and wait for a human (timeout counts as denied). Without `pod watch` running they wait until the timeout and are denied — that is fail-closed, not a bug.',
  '想免掉人工审批又要保持可审计：用 `pod grant issue` 签发限时/限作用域令牌。':
    'To skip the human step while staying auditable, issue a time-boxed, scope-limited token with `pod grant issue`.',
  '策略是刚从语料编译出来的话，先跑 `pod lint --policy <file>` 并人工复核一遍——执法改动直接影响 agent 能不能干活。':
    'If the policy was just compiled, run `pod lint --policy <file>` and review it — enforcement directly affects whether the agent can get work done.',
  '没有处于执法模式的 server（可能已经都在只录不拦）。':
    'No server is in enforcement mode (they may all be record-only already).',
  '没有处于只录不拦的 server（先用「接管」把 server 包进网关）。':
    'No server is in record-only mode (use "Take over" first to put servers behind the gateway).',
  '没有可用于执法的策略：`policies/` 下没有绑定 agent {agent} 且含 server 规则的策略文件。先跑 `pod policy draft --agent {agent} --out <file>` 并复核（当前审计语料 {corpus} 条）。':
    'No policy is ready for enforcement: no file under `policies/` is bound to agent {agent} and contains server rules. Run `pod policy draft --agent {agent} --out <file>` and review it first (the corpus currently holds {corpus} records).',
  '策略 {file} 的 server 规则是 allow:["*"]（等于全部放行）——直接切执法只会让人以为已经保护了。请先编译最小权限策略。':
    'The server rules in {file} are allow:["*"] (i.e. everything is permitted) — enforcing that would only create the illusion of protection. Compile a least-privilege policy first.',
  '执法计划不可执行': 'The enforcement plan is not applicable',
  '已切执法：网关现在会按策略判定 deny / approve / allow（未登记的一律拒绝）。':
    'Enforcement is on: the gateway now decides deny / approve / allow from the policy (anything unregistered is denied).',
  '命中 approve 的调用会挂起等审批；没在跑 `pod watch` 就会等超时被拒（fail-closed）。':
    'Calls that hit approve suspend for a human; without `pod watch` they time out and are denied (fail-closed).',
  '要退回可以用卡片上的「回到只录不拦」，或「还原配置」恢复到接管之前。':
    'To back out, use "Back to record-only", or "Restore config" to return to the pre-takeover state.',
  '已回到只录不拦：策略不变，只是不再阻断。':
    'Back to record-only: the policy is unchanged, it just does not block.',
  '还可以继续撤销：再点一次「还原配置」会退到上一步（当前 {mode}）。':
    'You can keep undoing: clicking "Restore config" again steps back one more (currently {mode}).',
  'pod agents enforce 需要 --harness <id>': 'pod agents enforce needs --harness <id>',
  '执法计划（dry-run；加 --yes 才真正改写包装命令）':
    'Enforcement plan (dry-run; add --yes to rewrite the wrapper command)',
  '回到只录不拦的计划（dry-run；加 --yes 才改写）':
    'Plan for going back to record-only (dry-run; add --yes to rewrite)',
  '执法策略：{path}（{servers} 个 server · {tools} 个工具 · allow {allow} / approve {approve} / deny {deny}）':
    'Enforcement policy: {path} ({servers} servers · {tools} tools · allow {allow} / approve {approve} / deny {deny})',
  '当前审计语料：{corpus} 条': 'Audit corpus: {corpus} records',
  '已切执法 {harness} → agent {agent}': 'Enforcement on for {harness} → agent {agent}',
  '已回到只录不拦 {harness} → agent {agent}': 'Back to record-only for {harness} → agent {agent}',
  '切执法失败：{error}': 'Switching to enforcement failed: {error}',
  '未知的 agents 子命令：{sub}（可用：scan / enroll / onboard / enforce / revert / forget）':
    'Unknown agents subcommand: {sub} (available: scan / enroll / onboard / enforce / revert / forget)',

  // ── guard 判定文案（packages/guard/src/detect.ts）──
  // 这些串带占位符，是 finding 的正文；英文模式下必须完整，不能中英混排。
  'MCP server "{name}" 从 npx 拉取 {pkg}{version}，上游每次发布都会进入本机':
    'MCP server "{name}" pulls {pkg}{version} through npx — every upstream release lands on this machine',
  '（未写版本）': ' (no version pinned)',
  'MCP server "{name}" 未经过 pod 网关——策略、审批、审计对它都不生效':
    'MCP server "{name}" bypasses the pod gateway — policy, approval and audit do not apply to it',
  'MCP server "{name}" 关闭了鉴权（DANGEROUSLY_OMIT_AUTH）——工具执行变成了无鉴权的网络接口':
    'MCP server "{name}" runs with authentication disabled (DANGEROUSLY_OMIT_AUTH) — tool execution becomes an unauthenticated network endpoint',
  'MCP server "{name}" 绑定 0.0.0.0——本机之外的进程也能连上它的工具执行面':
    'MCP server "{name}" binds 0.0.0.0 — processes beyond this machine can reach its tool-execution surface',
  'MCP server "{name}" 的端点 URL 无法解析，无法确认它连到哪里':
    'The endpoint URL of MCP server "{name}" cannot be parsed, so where it connects is unknown',
  'MCP server "{name}" 通过明文 HTTP 连到远程主机 {host}——token 与工具参数在链路上可读可改':
    'MCP server "{name}" reaches remote host {host} over plain HTTP — tokens and tool arguments are readable and modifiable on the wire',
  'MCP server "{name}" 连到远程主机 {host}——确认它强制鉴权，且只授予必需的工具':
    'MCP server "{name}" connects to remote host {host} — confirm it enforces authentication and exposes only the tools you need',
  '工作区 {root} 里有 {n} 个 MCP 配置：接受一次"信任此文件夹"就会以你的权限启动其中的 server':
    'Workspace {root} contains {n} MCP config(s): accepting "trust this folder" once starts their servers with your privileges',
  '钩子（{event}）命中风险规则 {id}：{why}{trusted}':
    'Hook ({event}) matched risk rule {id}: {why}{trusted}',
  '钩子内容可疑': 'suspicious hook content',
  '（来源在 trustedSources 里，已降级）': ' (source is in trustedSources; severity lowered)',
  '钩子用 "{flag}" 启动 agent——审批闸门被这个参数整条绕过':
    'A hook starts the agent with "{flag}" — this flag bypasses the human-approval gate entirely',
  'MCP server "{name}" 用 "{flag}" 启动子进程——审批闸门被这个参数整条绕过':
    'MCP server "{name}" starts a subprocess with "{flag}" — this flag bypasses the human-approval gate entirely',
  '发现 {n} 个第三方插件/技能目录：它们把提示词、脚本和钩子一起带进来，安装即接受全部三样':
    'Found {n} third-party plugin/skill directories: they ship prompts, scripts and hooks together, so installing accepts all three',
  '{file} 是长期记忆，但没有纳入 rules.memory.paths——被改写时不会有人知道，而它会影响之后每一次会话':
    '{file} is long-term memory that rules.memory.paths does not cover — it can be rewritten with nobody noticing, and it shapes every later session',
  '（{bytes} 字节）': ' ({bytes} bytes)',
  '{harness} 同时具备"读私密数据"与"向外发送"能力（致命三角的两条边：{private} → {egress}）——它读到的任何不可信内容都可能被发出去':
    '{harness} can both read private data and send outward (two legs of the lethal trifecta: {private} → {egress}) — anything untrusted it reads can leave the machine',
  '读私密：': 'Reads private data: ',
  '可外发：': 'Can send out: ',
  '同一份 {category}（{masked}）出现在 {n} 个配置里——出事时无法判断是谁做的，也无法单独吊销':
    'The same {category} ({masked}) appears in {n} configs — after an incident you cannot tell who did what, nor revoke just one of them',
  '{harness} 在本机上是装着的，但没有策略、身份或审计记录（发现的证据：{evidence}）':
    '{harness} is installed on this machine but has no policy, identity or audit record (evidence: {evidence})',
  '{harness} 有治理记录但没有审计链——它做过什么无法证明（managedBy: {by}）':
    '{harness} has governance records but no audit chain — what it did cannot be proven (managedBy: {by})',
  '尚未建立姿态基线：agent 配置、记忆文件、钩子被改写时不会报出来（攻击者只需要改一个参数就能把闸门悄悄摘掉）':
    'No posture baseline yet: rewrites of agent config, memory files and hooks go unreported (an attacker only has to change one parameter to quietly remove the gate)',
  '基线之后新增了 MCP server "{name}"（{file}）——确认这是你自己加的':
    'MCP server "{name}" appeared after the baseline ({file}) — confirm you added it yourself',
  'MCP server "{name}" 的启动命令与基线不一致——同名 server 可能被换成了另一个包（rug pull）':
    'The launch command of MCP server "{name}" differs from the baseline — the same name may now point at a different package (rug pull)',
  'rules.injection.block 是关的：工具响应里的注入内容会原样回到 agent 上下文（这正是 EchoLeak 类的入口）':
    'rules.injection.block is off: injected content in tool responses flows back into the agent context untouched (exactly the EchoLeak-class entry point)',
  'rules.egress 未启用，但本机有 {n} 个能向外发送的 server（{list}）——数据出机器前没有可判定的闸门':
    'rules.egress is disabled, yet {n} server(s) here can send data out ({list}) — nothing decidable stands between your data and the network',
  'rules.toolMetadata.block 是关的：工具描述里的隐藏指令不会被从 tools/list 摘掉，模型会直接读到':
    'rules.toolMetadata.block is off: hidden instructions in tool descriptions are not stripped from tools/list, so the model reads them directly',
  '未知威胁编号 {threat}（catalog 与 detect 不同步）':
    'Unknown threat id {threat} (catalog and detect are out of sync)',
  '  - 证据：`{evidence}`': '  - Evidence: `{evidence}`',
  '威胁模型 {list}': 'threat model {list}',
  // ── pod policy draft（草稿报告与策略 diff，会嵌进 pod harden 的交付物）──
  '# pod policy draft — 从录制语料生成的最小权限草稿':
    '# pod policy draft — least-privilege draft compiled from recorded calls',
  '工具名含破坏性动词 "{verb}"': 'the tool name contains a destructive verb: "{verb}"',
  '工具名含写/执行动词 "{verb}"': 'the tool name contains a write/exec verb: "{verb}"',
  '未命中高危动词（只读类）': 'no high-risk verb matched (read-only class)',
  '观测到敏感路径/密钥命中（强制 deny）':
    'a sensitive path or credential was observed, so this is forced to deny',
  '以下工具观测到敏感命中，已强制 deny：{list}':
    'These tools saw sensitive hits and were forced to deny: {list}',
  '## 策略 diff（baseline → draft）': '## Policy diff (baseline → draft)',
  '| server | tool | baseline | draft | 变化 |': '| server | tool | baseline | draft | change |',
  '新增': 'added',
  '收紧': 'tightened',
  '放宽': 'loosened',
  '移除': 'removed',
  '默认决策': 'default decision',
  '**汇总**：收紧 {tightened} · 新增 {added} · 移除 {removed} · 放宽 {loosened}':
    '**Totals**: tightened {tightened} · added {added} · removed {removed} · loosened {loosened}',
  // 默认规则里的命中原因（可在 rules.json 里改；用户自己写的说明原样显示）
  '钩子里出现网络出口': 'network egress inside the hook',
  '钩子建立持久化': 'the hook establishes persistence',
  '钩子改写 shell 启动文件': 'the hook rewrites shell startup files',
  '钩子执行编码/动态载荷': 'the hook executes an encoded/dynamic payload',
  '已从 tools/list 摘除': 'removed from tools/list',
  '工具描述里藏着指令': 'the tool description hides instructions',
  '工具描述指向凭据文件': 'the tool description points at credential files',
  '工具描述里带外部端点': 'the tool description carries an external endpoint',
  '覆盖既有指令的典型句式': 'a textbook phrase for overriding prior instructions',
  '同上': 'same as above',
  '同上（中文）': 'same as above (Chinese)',
  '要求隐瞒本身就是注入目标': 'asking for concealment is itself the injection goal',
  '直接谈论外泄': 'talks about exfiltration directly',
  '直白索取密钥': 'asks for the credential outright',
  '可能是讨论，也可能是攻击': 'may be discussion, may be an attack',
  '正常文档/讨论里很常见，只标记': 'common in normal docs and discussion; flagged only',
  '正常行文也会出现，只标记': 'shows up in ordinary prose; flagged only',
  '🔴 high — 现在就该处理': '🔴 high — fix now',
  '🟠 medium — 本周处理': '🟠 medium — fix this week',
  '🟡 low — 记录在案': '🟡 low — note it down',
  '配置里发现明文 {category}（{masked}）——任何能读这个文件的进程都拿到了它':
    'Plaintext {category} ({masked}) found in config — any process that can read this file now holds it',

  // ── guard 威胁目录（渲染时按 entry.title / entry.summary / … 查表）──
  // 这些键在 packages/i18n/data-keys.txt 里声明：覆盖率脚本据此要求它们都有英文词条，
  // 同时不会因为"代码里没有字面量 t('…')"而把它们误报成僵尸键。
  //
  // AG-01
  '明文凭据进了 agent / MCP 配置': 'Plaintext credentials in agent / MCP config',
  'API key、PAT、数据库口令直接写在 mcp.json / settings.json / mcp-manager.json 里。任何能读这些文件的进程（包括它自己要启动的 MCP server、IDE 扩展、同机恶意软件）都拿到了凭据。':
    'API keys, PATs and database passwords sit in plain sight in mcp.json / settings.json / mcp-manager.json. Anything that can read those files holds the credential — including the MCP servers they launch, IDE extensions, and other code on the same machine.',
  'pod scan 掩码识别 9 类密钥格式': 'pod scan recognises nine credential formats and prints them masked',
  '策略 secrets.deny_input_paths 拒绝读取敏感路径': 'The policy denies reads of sensitive paths through secrets.deny_input_paths',
  '把密钥迁到系统钥匙串 / secret 管理器，配置里只留引用':
    'Move the credential into the OS keychain or a secret manager; keep only a reference in config',
  '配置文件是分发物，凭据一旦落盘就等于进了版本历史与备份':
    'Config files get copied around; once a credential is on disk it is in your history and your backups',
  // AG-02
  'MCP server 来源未锁定版本': 'MCP server source is not version-pinned',
  'npx -y pkg 或 @latest 让上游每次发布直接进入本机。postmark-mcp 先跑 15 个干净版本、第 16 版才加 BCC 外发——版本不锁，你就没有"我装的那份"这个事实。':
    'npx -y pkg and @latest pull whatever upstream published today straight onto this machine. postmark-mcp ran 15 clean versions before version 16 added BCC exfiltration — without a pin, "the version I installed" is not a fact you have.',
  'pod 不校验 npm 包的签名与发布者；来源真实性要用户自己核对官方仓库':
    'pod does not verify npm package signatures or publishers; confirming the source really is the official repo is on you',
  'pod scan / pod posture packages.requireVersionPin 检查版本锁定':
    'pod scan / pod posture packages.requireVersionPin check whether versions are pinned',
  '把 npx / @latest 换成官方仓库的固定版本（pkg@x.y.z），或在本地锁 lockfile':
    'Replace npx / @latest with a pinned version from the official repo (pkg@x.y.z), or lock the package in a local lockfile',
  '版本锁定把"上游今天发了什么"变成可复核的确定事实':
    'Pinning turns "whatever upstream shipped today" into a checkable fact',
  // AG-03
  'MCP server 绕过网关直连': 'MCP server bypasses the gateway',
  'agent 配置里的 server 没走 pod 网关，策略、审批、审计对它全部无效。这是所有"边界完整性"问题的前提——只要有一条绕过，其余防线就只在部分流量上生效。':
    'A server in the agent config does not go through the pod gateway, so policy, approval and audit do not apply to it at all. This is the precondition for every boundary-integrity problem: one bypass, and the rest of your defences cover only part of the traffic.',
  'pod coverage --strict': 'pod coverage --strict',
  'pod scan checkBypass': 'pod scan checkBypass',
  'pod serve 在 MCP 边界执法': 'pod serve enforces at the MCP boundary',
  '用 onboarding 把直连的 server 包进网关':
    'Wrap the direct server through the gateway with onboarding',
  '只有经过的点才能拦；绕过网关的调用连审计记录都不存在':
    'Only traffic that passes a point can be blocked there; calls that bypass the gateway have no audit record at all',
  // AG-04
  '项目级 MCP 配置在打开文件夹时自动执行': 'Project-level MCP config runs when a folder is opened',
  '仓库里的 .mcp.json / .cursor/mcp.json / .vscode/mcp.json 被 clone 下来后，接受"工作区信任"这一个动作就足以让攻击者的命令以开发者权限启动。CurXecute 证明一次外部提示注入就能改写 mcp.json 并在下一次启动执行。':
    'Once a repo containing .mcp.json / .cursor/mcp.json / .vscode/mcp.json is cloned, one "trust this workspace" click is enough to start an attacker\'s command with developer privileges. CurXecute showed a single external prompt injection rewriting mcp.json to run on the next launch.',
  'pod 不阻断 harness 自己启动项目级 server 这个动作（那是 harness 的行为，不在 MCP 边界内）':
    'pod does not block the harness itself from launching project-level servers — that is harness behaviour, outside the MCP boundary',
  'pod onboard 把项目级 server 包进网关后，策略对它有约束':
    'Once pod onboard wraps a project-level server, policy applies to it',
  '把仓库里的 MCP 配置当作不可信输入：进仓库前审一遍，或改用用户级配置':
    'Treat MCP config inside a repo as untrusted input: review it before it enters the repo, or move to user-level config',
  '打开文件夹不等于同意执行陌生代码；这一步必须显式':
    'Opening a folder is not consent to execute unfamiliar code; that step has to be explicit',
  // AG-05
  '生命周期钩子携带网络出口 / 持久化 / 编码载荷':
    'Lifecycle hooks carry network egress / persistence / encoded payloads',
  '钩子把 shell 命令绑到 harness 事件上（会话启动、每次提交提示词、文件编辑），以宿主权限运行，且往往在用户和模型都看不见的时机触发。PromptArmor 的攻击链就是"恶意插件 + 钩子改写 permissions 文件"，把人工审批整条摘掉。':
    'Hooks bind shell commands to harness events (session start, every prompt, file edits). They run with host privileges, often at moments neither the user nor the model is watching. PromptArmor\'s chain was "malicious plugin + hook rewrites the permissions file", removing human approval entirely.',
  'pod 不执行钩子也不阻断钩子——钩子跑在 harness 里，不经过网关；能力边界是发现 + 取证 + 变更审计':
    'pod neither runs nor blocks hooks — they execute inside the harness and never cross the gateway; the boundary is detection, forensics and change auditing',
  'pod posture 采集钩子并按 rules.hookRisk.riskPatterns 判定':
    'pod posture collects hooks and judges them against rules.hookRisk.riskPatterns',
  '钩子内容进基线，新增/改动按 freeze 级别报警':
    'Hook content goes into the baseline; additions and edits alert at freeze severity',
  '确认钩子来源；给可信钩子加签名，把其余钩子移出风险规则之外':
    'Confirm where each hook came from; sign the ones you trust and move the rest out of the risk rules',
  '钩子是"配置即代码执行"——它比插件本身更值得冻结':
    'A hook is "config as code execution" — it deserves freezing more than the plugin itself',
  // AG-06
  'agent 以"跳过审批"模式运行': 'Agent runs in "skip approval" mode',
  '--dangerously-skip-permissions / --yolo / --trust-all-tools / DANGEROUSLY_OMIT_AUTH 这类开关把人类审批整条拿掉。s1ngularity 供应链攻击正是用这些 flag 把开发者本机的 AI CLI 变成无审批的侦察与打包工具。':
    'Flags like --dangerously-skip-permissions / --yolo / --trust-all-tools / DANGEROUSLY_OMIT_AUTH remove human approval entirely. The s1ngularity supply-chain attack used exactly these flags to turn local AI CLIs into unapproved reconnaissance and packaging tools.',
  'agent 自身的 CLI flag 不在 pod 控制范围内；pod 只能发现配置里的放宽项并报警':
    'The agent\'s own CLI flags are outside pod\'s control; pod can only surface and alert on the relaxed settings it can see in config',
  'pod serve 的 approve 闸门 + fail-closed 超时':
    'pod serve\'s approve gate with fail-closed timeout',
  'pod grant 的 JIT 令牌可替代交互审批':
    'pod grant JIT tokens can replace interactive approval',
  '去掉跳过审批的启动参数；需要自动化时改用 pod grant 签发的限时令牌':
    'Drop the skip-approval flag; when automation must bypass the prompt, use a time-boxed token issued by pod grant instead',
  '跳过审批把"人在回路"换成"任何能影响 agent 的内容都在回路"':
    'Skipping approval replaces "a human in the loop" with "anything that can influence the agent is in the loop"',
  // AG-07
  '长期记忆文件可被写入且未纳管': 'Long-term memory is writable and unmanaged',
  'CLAUDE.md / AGENTS.md 之类的长期记忆影响的是之后每一次会话。一次投毒不是一条坏回复，而是一个持续生效的立场。记忆文件和普通数据一样可写，却比普通数据耐用得多。':
    'Long-term memory such as CLAUDE.md / AGENTS.md shapes every session that follows. Poisoning it is not one bad reply, it is a standing position. Memory files are as writable as ordinary data but far more durable.',
  'pod 不理解记忆内容语义，只保证"你看到的和上次是不是同一份"；语义级投毒检测不在覆盖范围':
    'pod does not understand memory semantics; it only guarantees "what you see is the same as last time". Semantic poisoning detection is out of scope',
  'pod posture memory.paths 进基线，漂移按 high 报':
    'pod posture puts rules.memory.paths into the baseline; drift reports at high',
  '把记忆文件纳入基线，并在评审后合并变更':
    'Bring memory files into the baseline and merge changes only after review',
  '记忆写入比普通数据更需要人工确认来源——它会影响后续所有决策':
    'A memory write deserves more source-checking than ordinary data — it influences every later decision',
  // AG-08
  '远程 / HTTP 形态的 MCP 端点未鉴权': 'Remote / HTTP MCP endpoint lacks authentication',
  'MCP 的 Streamable HTTP / SSE 传输把工具执行暴露成网络接口。MCP Inspector 的 CVE-2025-49596（CVSS 9.4）就是绑定 0.0.0.0 且无鉴权，一次 CSRF 直接变成远程代码执行；oatpp-mcp 的 CVE-2025-6515 则用可预测 session id 做提示词劫持。':
    'MCP\'s Streamable HTTP / SSE transports expose tool execution as a network interface. MCP Inspector\'s CVE-2025-49596 (CVSS 9.4) bound 0.0.0.0 without authentication, turning one CSRF into remote code execution; oatpp-mcp\'s CVE-2025-6515 hijacks prompts through predictable session ids.',
  '第三方 server 自己的监听地址与鉴权策略 pod 看不到，只能从配置里发现线索（0.0.0.0 / 关闭鉴权的开关）':
    'pod cannot see a third-party server\'s listen address or auth policy — only the clues in your config (0.0.0.0, auth-disable flags)',
  'pod serve --http 绑定 127.0.0.1 + token；网关不暴露 stdio 之外的裸执行面':
    'pod serve --http binds 127.0.0.1 with a token; the gateway exposes no raw execution surface beyond stdio',
  '远程端点只绑本地回环并强制鉴权；确需暴露时套在 pod 网关后面':
    'Bind remote endpoints to loopback and require authentication; if they must be exposed, put them behind the pod gateway',
  '工具执行暴露成网络接口就是 RCE 面；无鉴权等于把执行权挂公网':
    'Exposing tool execution as a network interface is an RCE surface; without authentication you have published execution rights',
  // AG-09
  '致命三角：私密数据 + 不可信输入 + 外发通道':
    'Lethal trifecta: private data + untrusted input + egress path',
  'Simon Willison 的"致命三角"：同一个 agent 同时能读私密数据、会读到攻击者可控的内容、又能把数据发出去，就一定能被诱导外泄。GitHub MCP 的私有仓库泄露就是标准案例——恶意 issue 让 agent 把私有仓库信息写进公开 PR。':
    'Simon Willison\'s "lethal trifecta": if one agent can read private data, can read attacker-controlled content, and can send data out, it can always be talked into exfiltrating. The GitHub MCP private-repo leak is the canonical case — a malicious issue made the agent write private repository data into a public PR.',
  '三角里"不可信输入"这一边在 pod 看不到（server 的响应内容不经过能力判定）；模型对没见过的措辞仍然会中招':
    'The "untrusted input" leg is invisible to pod (server responses are not capability-judged); and a model still falls for wording it has never seen',
  'pod graph toxic 在能力图上找 source→sink 毒性链':
    'pod graph toxic finds source→sink paths on the capability graph',
  'policy deny_output_matching 拦密钥外发': 'policy deny_output_matching blocks credentials on the way out',
  'injection.signals 分级阻断已知注入句式':
    'injection.signals blocks known injection phrasings by severity',
  '拆三角：把私密数据 server 与外发 server 分给不同 agent，或对写入类工具强制 approve':
    'Break the triangle: give the private-data server and the egress server to different agents, or force approve on write-capable tools',
  '三条边少一条，攻击链就断；拆权限比检测提示词可靠':
    'Remove one leg and the chain breaks; splitting permissions is more reliable than detecting prompts',
  // AG-10
  '多个 agent / server 共用同一份凭据': 'Multiple agents / servers share one credential',
  '共享令牌意味着出事时无法回答"是谁做的"，也无法单独吊销。Nx 事件里被偷的 GitHub/npm token 能横向把数千个仓库改成公开，正是因为一份凭据覆盖了远超需要的范围。':
    'A shared token means that after an incident you cannot say who did it, nor revoke just one consumer. In the Nx incident, stolen GitHub/npm tokens made thousands of repos public precisely because one credential covered far more than it needed to.',
  'pod identity 给每个 agent 一对 ed25519 密钥': 'pod identity gives every agent its own ed25519 keypair',
  'pod delegate 委托链逐跳收窄': 'pod delegate narrows the delegation chain hop by hop',
  'pod grant JIT 令牌带 TTL 与作用域': 'pod grant JIT tokens carry a TTL and a scope',
  '每个 agent 一份身份；需要共享能力时走签名委托并把范围收窄':
    'One identity per agent; when capabilities must be shared, use signed delegation and narrow the scope',
  '归因能力来自身份唯一性；共享凭证让审计链只能证明"某台机器做了"':
    'Attribution comes from identity being unique; with a shared credential the audit chain can only prove "some machine did it"',
  // AG-11
  '影子 agent：有 agent 在跑，但没有任何治理记录': 'Shadow agent: something is running with no governance record',
  '本机同时装了好几个 harness，只有一部分被纳入策略/审计。控制台看到的"全部资产"其实是"愿意露面的资产"，剩下的暴露面既不在策略里也不在证据里。':
    'Several harnesses are installed here and only some are under policy/audit. The console\'s "all assets" is really "the assets that showed up" — the rest are in neither your policy nor your evidence.',
  'pod scan 发现已安装的 harness': 'pod scan discovers installed harnesses',
  'pod posture identities 对比策略/审计/身份三个来源':
    'pod posture identities compares the policy, audit and identity sources',
  '给每个在用的 harness 建身份并挂策略；不用的直接卸载':
    'Give every harness you use an identity and a policy; uninstall the ones you do not use',
  '资产不清时，治理只能覆盖一部分流量，而攻击者只需要那一部分之外的一条路':
    'Without a complete asset list you govern part of the traffic, and an attacker only needs one path outside that part',
  // AG-12
  'agent 配置未冻结，可被静默降级': 'Agent config is not frozen; it can be silently downgraded',
  '攻击者不需要创造新的恶意动作，只要改一个参数：把审批关掉、把内部地址换成公开地址、把密钥引用换成明文。agent 仍然"正确"完成任务，安全态势已经被摘掉——这正是 CurXecute 的落点。':
    'An attacker does not need a new malicious action, only one changed parameter: turn approval off, swap an internal address for a public one, replace a secret reference with plaintext. The agent still "correctly" finishes the task while the security posture has been removed — exactly CurXecute\'s landing spot.',
  'pod posture freeze 把冻结项记进基线哈希':
    'pod posture freeze records frozen items into the baseline hash',
  '漂移写进同一条哈希链（config-change）':
    'Drift goes into the same hash chain (config-change)',
  '冻结所有 harness 的配置路径，把漂移检查挂进定时任务或 CI':
    'Freeze the config paths of every harness and wire the drift check into cron or CI',
  '配置漂移是最安静的攻击面：动作合法、意图不在日志里':
    'Config drift is the quietest attack surface: the action is legitimate and the intent never reaches a log',
  // AG-13
  '插件 / 技能市场来源未固定': 'Plugin / skill marketplace source is not pinned',
  'Agent Skills 这类分发物把提示词、脚本和钩子打包在一起，装进来就等于同时接受了三样东西。Snyk 对某市场数千个 skill 的扫描发现 36% 含提示词注入、1467 个恶意载荷。':
    'Distribution units like Agent Skills bundle prompts, scripts and hooks together, so installing one accepts all three. Snyk\'s scan of thousands of skills in one marketplace found 36% containing prompt injection and 1467 malicious payloads.',
  'pod 不审查插件/skill 正文（提示词注入在自然语言里），只审查它带来的钩子与命令':
    'pod does not review plugin/skill content (prompt injection lives in natural language), only the hooks and commands they bring',
  'hookRisk.watchPaths 覆盖插件目录下的钩子文件':
    'hookRisk.watchPaths covers hook files under plugin directories',
  'hookRisk.trustedSources 决定是否降级': 'hookRisk.trustedSources decides whether severity is lowered',
  '插件目录纳入钩子与配置冻结范围；升级后必须复核':
    'Bring plugin directories into hook and config freezing; re-review after every upgrade',
  '插件以"更新"的名义换掉钩子，是最难被注意到的持久化方式':
    'Replacing hooks under the name of an "update" is the hardest persistence to notice',
  // AG-14
  'MCP server 启动命令与基线不一致（rug pull）': 'MCP server launch command differs from the baseline (rug pull)',
  '同名 server 被换成另一个包、或参数被改。工具描述可以在安装后被悄悄改写（rug pull），用户第 1 天批准的那个工具，第 7 天已经在做别的事。':
    'The same server name now points at a different package, or its arguments changed. Tool descriptions can be rewritten after installation (rug pull): the tool you approved on day 1 is doing something else on day 7.',
  'pod posture packages.requireIntegrity 比对 command+args 指纹':
    'pod posture packages.requireIntegrity compares the command+args fingerprint',
  'gateway 启动前校验策略 source 白名单': 'The gateway validates the policy source allowlist before startup',
  '打开来源完整性检查并冻结当前 server 指纹':
    'Turn on source integrity checking and freeze the current server fingerprints',
  'rug pull 攻击的前提是"没人比过上一次的命令行"':
    'A rug pull requires that nobody compared the command line with last time',
  // AG-15
  '注入阻断与 egress 判定未启用，但存在外发能力的 server':
    'Injection blocking and egress decisions are off while egress-capable servers exist',
  '工具响应里带回的内容是间接注入的主要入口（EchoLeak 是零点击版本）；egress 判定是数据出机器前最后一道可判定闸门。两者默认关闭时，防线就只剩"模型自己不被骗"。':
    'Content returned in tool responses is the main route for indirect injection (EchoLeak is the zero-click version); the egress decision is the last checkable gate before data leaves the machine. With both off by default, your defence is "the model will not be fooled".',
  '词表只能抓已知措辞；egress 只判定参数里出现的主机，看不到 server 内部自己发的请求':
    'Signatures only catch known phrasings; egress judges only hosts visible in arguments, not requests the server makes on its own',
  'rules.injection 分级子串匹配（默认阻断 high）':
    'rules.injection matches phrases by severity (blocks high by default)',
  'rules.egress allowHosts/denyHosts 判定参数里的主机':
    'rules.egress allowHosts/denyHosts judge hosts appearing in arguments',
  '确认 injection.block 与 egress 判定已打开，并按自己的 provider 列表收紧 allowHosts':
    'Confirm injection.block and the egress decision are on, and tighten allowHosts to your own provider list',
  '这两项是 egress 侧唯一可判定、可复现的闸门；关着等于只剩模型自觉':
    'These two are the only decidable, reproducible gates on the egress side; with them off, only the model\'s judgement stands',
  // AG-16
  '审计覆盖缺口：harness 在网关之外活动': 'Audit coverage gap: harness activity outside the gateway',
  '"看起来在记、其实没记"比"没记"更危险：链断裂后追加会被拒绝，agent 照常工作、本地一条都不再落。发现了 harness 却没有任何审计链，等价于出事时只能靠回忆。':
    '"Looks like it is recording" is more dangerous than "not recording": once the chain breaks, appends are refused while the agent keeps working and nothing lands locally. Finding a harness with no audit chain at all means that after an incident you can only rely on memory.',
  'pod posture auditHealth 检查断链与长时间无写入':
    'pod posture auditHealth checks for broken chains and long silence',
  'pod verify-audit / export-evidence 可独立校验':
    'pod verify-audit / export-evidence can be verified independently',
  '给每个 harness 接上记录通道，并把 auditHealth 期望活跃度按 agent 配好':
    'Connect a recording channel for every harness and set the expected auditHealth activity per agent',
  '证据的可用性取决于"断的那一刻有没有人告诉你"':
    'Evidence is only as good as someone telling you at the moment it breaks',
  // AG-17
  '工具描述投毒面：server 未走网关时摘除规则不生效':
    'Tool-description poisoning surface: removal rules do nothing when the server bypasses the gateway',
  '工具描述是模型直接读的自由文本，也是唯一能"不用被调用就影响行为"的通道。pod 的 toolMetadata 规则会在 tools/list 阶段把命中工具摘掉——但只在流量经过网关时有效。':
    'Tool descriptions are free text the model reads directly, and the only channel that changes behaviour without being called. pod\'s toolMetadata rules strip matching tools at the tools/list stage — but only when traffic crosses the gateway.',
  '摘除是启发式的（正则），编码/改写后的恶意描述会漏；且必须有网关在中间':
    'Stripping is heuristic (regex), so encoded or reworded malicious descriptions slip through; and a gateway has to be in the path',
  'rules.toolMetadata.suspiciousPatterns + 在 tools/list 阶段摘除命中工具（默认 high）':
    'rules.toolMetadata.suspiciousPatterns + stripping matching tools at tools/list (high by default)',
  '让所有 server 走网关，并保持 toolMetadata.block 打开':
    'Route every server through the gateway and keep toolMetadata.block on',
  '工具描述一旦进了上下文就没有撤回按钮；摘除必须在它进入之前发生':
    'Once a tool description is in context there is no undo button; removal has to happen before it gets there',
  // AG-18
  'MCP server 以宿主完整权限运行（无沙箱）': 'MCP server runs with full host privileges (no sandbox)',
  'MCP server 是普通进程，拿到的是启动它的用户权限。一次投毒就是一次完整的本地代码执行——这也是 Amazon Q / Nx 事件里"差点删掉整台机器"的原因。':
    'An MCP server is an ordinary process holding the privileges of whoever launched it. One poisoning is full local code execution — which is why the Amazon Q / Nx incidents nearly wiped machines.',
  'pod 不做沙箱/容器隔离（明确的非目标）。需要强隔离时用平台原生沙箱或容器，pod 的策略与证据可以叠在上面':
    'pod does not sandbox or containerise (an explicit non-goal). For hard isolation use the platform sandbox or a container; pod\'s policy and evidence layer on top',
  '把高权限 server 放进容器/沙箱；或者只给它一份最小权限的独立凭据':
    'Put high-privilege servers in a container or sandbox, or give each one a separate least-privilege credential',
  '本地优先的取舍是"网关进程内转发"，强隔离必须由外部承担':
    'The local-first trade-off is in-process forwarding; hard isolation has to come from outside',
}
