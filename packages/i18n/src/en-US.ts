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
}
