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
}
