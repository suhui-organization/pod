#!/usr/bin/env node
/**
 * pod CLI v0 骨架（Phase 0）。
 * 子命令：
 *   pod init [--template baseline|record]                     初始化 ~/.pod（示例策略）
 *   pod serve                    启动网关（MCP stdio 代理）
 *     --agent <name>              agent 身份
 *     --server <name>             server 名（策略求值用）
 *     --policy <path>             策略 JSON 文件
 *     --command <cmd>             真实 MCP server 启动命令
 *     --arg <value>               可重复，传给真实 server 的参数
 *     --audit-dir <path>          审计输出目录（默认 ~/.pod/audit）
 *
 * 注意：网关进程的 stdout 被 MCP 协议占用，所有日志必须走 stderr。
 */
import { parseArgs } from 'node:util';
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { AuditLog, appendToAuditFile, loadAuditFile } from '@podsec/audit';
import type { Policy } from '@podsec/policy';
import { createStdioProxy, createHttpProxy } from '@podsec/gateway';
import { scanMachine, renderMarkdown, checkBypass } from '@podsec/scan';
import { lintPolicy } from '@podsec/policy';
import { createFileApprovalProvider, decideApproval, listPendingApprovals } from './approval.js';
import { runSync, pullPolicies } from './sync.js';
import {
  buildTimeline,
  renderTimeline,
  verifyAll,
  renderVerifyReport,
  exportEvidence,
  verifyEvidenceBundle,
  type TimelineOptions,
} from './evidence.js';
import { loadAlertConfig, createAlertChecker, type AlertEvent } from './alert.js';

const POD_HOME = join(homedir(), '.pod');

function podPath(...parts: string[]): string {
  return join(POD_HOME, ...parts);
}

/** 策略模板库：pod init --template <name> 一键生成 */
const TEMPLATES: Record<string, { label: string; policy: Policy }> = {
  baseline: {
    label: '标准 OPC 基线（最小权限 + 敏感信息防线 + 审批闸门）',
    policy: {
      version: '0.1.0',
      agent: 'openclaw-main',
      defaultDecision: 'deny',
      servers: {
        filesystem: {
          allow: ['read_file', 'list_directory', 'search_files', 'get_file_info'],
          approve: ['write_file', 'edit_file'],
          deny: ['delete_file'],
          // T4：来源白名单——启动命令不匹配时拒绝启动
          source: { command: 'mcp-server-filesystem' },
        },
      },
      secrets: {
        // P0（T2）：敏感路径参数直接拒绝
        deny_input_paths: ['~/.ssh', '.env', 'credentials', 'id_rsa', 'id_ed25519', '.aws', 'known_hosts'],
        // P0（T2）：工具响应命中密钥正则则阻断
        deny_output_matching: [
          'ghp_[A-Za-z0-9]{36}',
          'github_pat_[A-Za-z0-9_]{22,}',
          'sk-[A-Za-z0-9]{20,}',
          'sk-ant-[A-Za-z0-9-]{20,}',
          'AKIA[0-9A-Z]{16}',
          'xox[baprs]-[A-Za-z0-9-]{10,}',
          'AIza[0-9A-Za-z_-]{35}',
        ],
      },
    },
  },
  record: {
    label: '采集模式（只录不拦，配合 pod record）',
    policy: {
      version: '0.1.0',
      agent: 'openclaw-main',
      servers: { '*': { allow: ['*'] } },
    },
  },
};

const EXAMPLE_POLICY: Policy = {
  version: '0.1.0',
  agent: 'openclaw-main',
  defaultDecision: 'deny',
  servers: {
    filesystem: {
      allow: ['read_file', 'list_directory', 'search_files', 'get_file_info'],
      approve: ['write_file', 'edit_file'],
      deny: ['delete_file'],
    },
    github: {
      allow: ['create_issue'],
    },
  },
  secrets: {
    // P0（T2）：敏感路径参数直接拒绝；工具响应命中正则则阻断
    deny_input_paths: ['~/.ssh', '.env', 'credentials', 'id_rsa', '.aws'],
    deny_output_matching: ['ghp_[A-Za-z0-9]{36}', 'sk-[A-Za-z0-9]{20,}', 'AKIA[0-9A-Z]{16}'],
  },
};

function log(message: string): void {
  console.error(`[pod] ${message}`);
}

async function cmdInit(template: string | undefined): Promise<void> {
  mkdirSync(podPath('policies'), { recursive: true });
  mkdirSync(podPath('audit'), { recursive: true });
  const name = template ?? 'example';
  const policyFile = podPath('policies', `${name}.json`);
  if (!existsSync(policyFile)) {
    if (template && TEMPLATES[template]) {
      writeFileSync(policyFile, JSON.stringify(TEMPLATES[template]!.policy, null, 2) + '\n', 'utf8');
      log(`template "${template}": ${TEMPLATES[template]!.label}`);
    } else if (template && !TEMPLATES[template]) {
      log(`未知模板 "${template}"，可用: ${Object.keys(TEMPLATES).join(', ')}`);
      return;
    } else {
      writeFileSync(policyFile, JSON.stringify(EXAMPLE_POLICY, null, 2) + '\n', 'utf8');
    }
  }
  log(`initialized ${POD_HOME}`);
  log(`policy: ${policyFile}`);
}

interface ServeOptions {
  agent: string;
  server: string;
  policy: string;
  command: string;
  args: string[];
  auditDir: string;
  pendingDir: string;
  approvalTimeoutSec: number;
  alertConfig?: string;
  transport: 'stdio' | 'http';
  port: number;
}

async function cmdServe(opts: ServeOptions): Promise<void> {
  const policy = JSON.parse(readFileSync(opts.policy, 'utf8')) as Policy;

  const auditDir = opts.auditDir;
  mkdirSync(auditDir, { recursive: true });
  const auditPath = join(auditDir, `${opts.server}.jsonl`);
  const alertConfig = loadAlertConfig(opts.alertConfig);
  const alertCheck = alertConfig ? createAlertChecker(alertConfig, async (e: AlertEvent) => {
    log(`ALERT [${e.severity}] ${e.kind}: ${e.message}`);
    await fetch(alertConfig.webhook_url, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(e),
    });
  }) : null;
  const audit = existsSync(auditPath)
    ? loadAuditFile(auditPath, policy.version, { onAppend: (entry) => { appendToAuditFile(auditPath, entry); alertCheck?.(entry); } })
    : new AuditLog(policy.version, { onAppend: (entry) => { appendToAuditFile(auditPath, entry); alertCheck?.(entry); } });

  const approval = createFileApprovalProvider({
    pendingDir: opts.pendingDir,
    timeoutMs: opts.approvalTimeoutSec * 1000,
    onRequest: (req) => {
      log(`APPROVAL NEEDED #${req.id}: server=${req.server} tool=${req.tool}`);
      log(`  approve: pod approve --id ${req.id} [--reason <why>]`);
      log(`  deny:    pod deny --id ${req.id} [--reason <why>]`);
    },
  });

  const server = await createStdioProxy({
    agent: opts.agent,
    serverName: opts.server,
    policy,
    audit,
    approval,
    command: opts.command,
    args: opts.args,
  });

  log(`serving "${opts.server}" for agent "${opts.agent}" (audit: ${auditPath})`);
  log(`upstream: ${opts.command} ${opts.args.join(' ')}`);
  log(`pending approvals: ${opts.pendingDir} (timeout ${opts.approvalTimeoutSec}s)`);

  if (opts.transport === 'http') {
    const result = await createHttpProxy({
      agent: opts.agent,
      serverName: opts.server,
      policy,
      audit,
      approval,
      command: opts.command,
      args: opts.args,
      port: opts.port,
      host: '127.0.0.1',
      log,
    });
    log(`gateway ready on ${result.url} (HTTP, resident)`);
    log('agent-side config: point your agent\'s MCP server at the URL above');
    return;
  }
  const { StdioServerTransport } = await import('@modelcontextprotocol/sdk/server/stdio.js');
  await server.connect(new StdioServerTransport());
  log('gateway ready on stdio; waiting for agent…');
}

interface RecordOptions {
  config: string;
  server: string;
  agent: string;
  policy?: string;
  auditDir: string;
}

/** 从 dsh-mcp-manager 格式的配置里找 server 条目 */
function findMcpServer(
  configPath: string,
  name: string,
): { command: string; args: string[]; env?: Record<string, string> } {
  const raw = JSON.parse(readFileSync(configPath, 'utf8')) as {
    servers?: Array<{
      name?: string;
      id?: string;
      transport?: string;
      command?: string;
      args?: string[];
      env?: Record<string, string>;
    }>;
  };
  const servers = raw.servers ?? [];
  const hit = servers.find((s) => s.name === name || s.id === name);
  if (!hit) {
    const available = servers.map((s) => s.name ?? s.id).filter(Boolean).join(', ');
    throw new Error(`server "${name}" not found in ${configPath}; available: ${available || '(none)'}`);
  }
  if (hit.transport && hit.transport !== 'stdio') {
    throw new Error(`server "${name}" uses transport "${hit.transport}"; only stdio is supported in v0`);
  }
  if (!hit.command) {
    throw new Error(`server "${name}" has no command`);
  }
  return { command: hit.command, args: hit.args ?? [], env: hit.env };
}

async function cmdRecord(opts: RecordOptions): Promise<void> {
  const upstream = findMcpServer(opts.config, opts.server);

  const policy: Policy = opts.policy
    ? (JSON.parse(readFileSync(opts.policy, 'utf8')) as Policy)
    : {
        version: '0.1.0',
        agent: opts.agent,
        // 未提供策略时全部标注 allow（record-only 不阻断，仅作中性标注）
        servers: { [opts.server]: { allow: ['*'] } },
      };

  const auditDir = opts.auditDir;
  mkdirSync(auditDir, { recursive: true });
  const auditPath = join(auditDir, `${opts.server}.jsonl`);
  const audit = existsSync(auditPath)
    ? loadAuditFile(auditPath, policy.version, { onAppend: (entry) => appendToAuditFile(auditPath, entry) })
    : new AuditLog(policy.version, { onAppend: (entry) => appendToAuditFile(auditPath, entry) });

  const server = await createStdioProxy({
    agent: opts.agent,
    serverName: opts.server,
    policy,
    audit,
    recordOnly: true,
    command: upstream.command,
    args: upstream.args,
    env: { ...process.env, ...(upstream.env ?? {}) } as Record<string, string>,
  });

  log(`recording "${opts.server}" (record-only, nothing is blocked)`);
  log(`upstream: ${upstream.command} ${upstream.args.join(' ')}`);
  log(`audit: ${auditPath}`);

  const { StdioServerTransport } = await import('@modelcontextprotocol/sdk/server/stdio.js');
  await server.connect(new StdioServerTransport());
  log('recorder ready on stdio; waiting for agent…');
  log('agent-side config: point your agent\'s MCP server at this process (see docs/agent-onboarding.md)');
}

interface AuditOptions {
  server?: string;
  tail: number;
  auditDir: string;
}

async function cmdAudit(opts: AuditOptions): Promise<void> {
  const files = readdirSync(opts.auditDir)
    .filter((f) => f.endsWith('.jsonl'))
    .sort();
  if (files.length === 0) {
    log(`no audit files in ${opts.auditDir}`);
    return;
  }
  const matched = opts.server
    ? files.filter((f) => f === `${opts.server}.jsonl`)
    : files;
  if (opts.server && matched.length === 0) {
    log(`no audit file for server "${opts.server}" in ${opts.auditDir} (have: ${files.join(', ')})`);
    return;
  }
  for (const file of matched) {
    const path = join(opts.auditDir, file);
    const log_ = loadAuditFile(path, ''); // 校验链（policyVersion 仅用于构造，不影响校验）
    const entries = log_.entries.slice(-opts.tail);
    log(`${file}: ${log_.entries.length} entries (chain verified, last ${entries.length})`);
    for (const e of entries) {
      const enforced = e.enforced === false ? 'rec' : 'enf';
      log(
        `  #${String(e.seq).padStart(4)} ${e.ts} ${e.decision.padEnd(7)} ${e.outcome.padEnd(7)} ` +
          `${enforced} ${e.tool}${e.reason ? `  — ${e.reason}` : ''}`,
      );
    }
  }
}

interface DecideOptions {
  id: string;
  approved: boolean;
  approver: string;
  reason?: string;
  pendingDir: string;
}

function cmdDecide(opts: DecideOptions): void {
  const pendingDir = opts.pendingDir;
  mkdirSync(pendingDir, { recursive: true });
  decideApproval(pendingDir, opts.id, {
    approved: opts.approved,
    approver: opts.approver,
    reason: opts.reason,
  });
  log(`${opts.approved ? 'approved' : 'denied'} ${opts.id} by ${opts.approver}`);
}

function cmdPending(pendingDir: string): void {
  mkdirSync(pendingDir, { recursive: true });
  const list = listPendingApprovals(pendingDir);
  if (list.length === 0) {
    log('no pending approvals');
    return;
  }
  log(`${list.length} pending approval(s):`);
  for (const p of list) {
    log(`  ${p.id}  server=${p.server} tool=${p.tool}  →  pod approve --id ${p.id} | pod deny --id ${p.id}`);
  }
}

function cmdLint(policyPath: string): void {
  const policy = JSON.parse(readFileSync(policyPath, 'utf8')) as Policy;
  const issues = lintPolicy(policy);
  if (issues.length === 0) {
    log(`✅ ${policyPath}: 策略检查通过（无问题）`);
    return;
  }
  for (const i of issues) {
    const tag = i.severity === 'error' ? '❌' : i.severity === 'warn' ? '⚠️' : 'ℹ️';
    log(`${tag} [${i.severity.toUpperCase()}] ${i.where}: ${i.message}`);
  }
  log(`${issues.filter((x) => x.severity === 'error').length} error(s), ${issues.filter((x) => x.severity === 'warn').length} warning(s)`);
  if (issues.some((x) => x.severity === 'error')) process.exitCode = 1;
}

function cmdDoctor(policyPath: string | undefined): void {
  log('pod doctor — 环境与配置自检');
  if (policyPath) {
    try {
      cmdLint(policyPath);
    } catch (e) {
      log(`❌ 策略文件不可读: ${e instanceof Error ? e.message : String(e)}`);
      process.exitCode = 1;
    }
  }
  // 防绕过检查（T 边界完整性）
  const bypass = checkBypass(homedir());
  if (bypass.length === 0) {
    log('✅ 未发现绕过网关的 MCP server');
  } else {
    log(`⚠️ ${bypass.length} 个 MCP server 未经过 pod 网关（agent 可直连绕过策略/审计）:`);
    for (const b of bypass) log(`   - ${b.file} → "${b.server}" (${b.command})`);
  }
  // 云配置
  const cloudPath = join(homedir(), '.pod', 'cloud.json');
  if (existsSync(cloudPath)) {
    try {
      const cfg = JSON.parse(readFileSync(cloudPath, 'utf8')) as { api_url?: string; agent_id?: number };
      log(`✅ cloud.json: api=${cfg.api_url} agent=${cfg.agent_id}`);
    } catch {
      log('❌ cloud.json 解析失败');
    }
  } else {
    log('ℹ️ 未配置 cloud.json（pod sync/pull-policy 不可用，本地功能不受影响）');
  }
  // 审计目录
  const auditDir = podPath('audit');
  log(existsSync(auditDir) ? `✅ 审计目录: ${auditDir}` : `ℹ️ 审计目录不存在（首次 record/serve 时创建）: ${auditDir}`);
}

function cmdTimeline(opts: TimelineOptions): void {
  const { entries, broken } = buildTimeline(opts);
  process.stdout.write(renderTimeline(entries, broken) + '\n');
  if (broken.length > 0) process.exitCode = 1;
}

function cmdVerifyAudit(auditDir: string, out: string | undefined): void {
  const results = verifyAll(auditDir);
  const report = renderVerifyReport(results, auditDir);
  if (out) {
    writeFileSync(out, report, 'utf8');
    log(`自检报告已写入: ${out}`);
  }
  process.stdout.write(report + '\n');
  if (results.some((r) => !r.ok)) process.exitCode = 1;
}

function cmdExportEvidence(auditDir: string, policyDir: string, outPath: string): void {
  const bundle = exportEvidence({ auditDir, policyDir, outPath });
  log(`证据包已导出: ${outPath}`);
  log(`  审计文件: ${Object.keys(bundle.audits).length} 个 | 策略快照: ${Object.keys(bundle.policies).length} 个`);
  log(`  顶层哈希: ${bundle.top_level_hash.slice(0, 16)}…`);
  log(`  验证: pod verify-evidence ${outPath}`);
}

function cmdVerifyEvidence(path: string): void {
  const r = verifyEvidenceBundle(path);
  if (r.ok) log(`✅ 证据包有效（顶层哈希匹配，未被修改）: ${path}`);
  else {
    log(`❌ 证据包校验失败: ${r.reason ?? ''}`);
    process.exitCode = 1;
  }
}

function cmdScan(json: boolean): void {
  const result = scanMachine({ home: homedir() });
  if (json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    process.stdout.write(renderMarkdown(result) + '\n');
  }
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    args: normalizePodArgs(process.argv.slice(2)),
    allowPositionals: true,
    options: {
      agent: { type: 'string' },
      server: { type: 'string' },
      policy: { type: 'string' },
      config: { type: 'string' },
      command: { type: 'string' },
      arg: { type: 'string', multiple: true },
      'audit-dir': { type: 'string' },
      'pending-dir': { type: 'string' },
      'approval-timeout': { type: 'string' },
      id: { type: 'string' },
      approver: { type: 'string' },
      reason: { type: 'string' },
      tail: { type: 'string' },
      json: { type: 'boolean' },
      'api-url': { type: 'string' },
      'agent-id': { type: 'string' },
      'sync-token': { type: 'string' },
      'out-dir': { type: 'string' },
      'alert-config': { type: 'string' },
      tool: { type: 'string' },
      since: { type: 'string' },
      limit: { type: 'string' },
      out: { type: 'string' },
      'policy-dir': { type: 'string' },
      template: { type: 'string' },
      transport: { type: 'string' },
      port: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  const cmd = positionals[0];
  if (values.help || !cmd) {
    console.error(usage());
    process.exit(cmd ? 0 : 1);
  }

  if (cmd === 'init') {
    await cmdInit(values.template);
    return;
  }

  if (cmd === 'serve') {
    if (!values.agent || !values.server || !values.policy || !values.command) {
      console.error('pod serve requires --agent --server --policy --command');
      console.error(usage());
      process.exit(1);
    }
    await cmdServe({
      agent: values.agent,
      server: values.server,
      policy: values.policy,
      command: values.command,
      args: values.arg ?? [],
      auditDir: values['audit-dir'] ?? podPath('audit'),
      pendingDir: values['pending-dir'] ?? podPath('pending'),
      approvalTimeoutSec: values['approval-timeout'] ? Number.parseInt(values['approval-timeout'], 10) : 300,
      alertConfig: values['alert-config'],
      transport: values.transport === 'http' ? 'http' : 'stdio',
      port: values.port ? Number.parseInt(values.port, 10) : 8787,
    });
    return;
  }

  if (cmd === 'approve' || cmd === 'deny') {
    if (!values.id) {
      console.error(`pod ${cmd} requires --id <approval-id>`);
      console.error(usage());
      process.exit(1);
    }
    cmdDecide({
      id: values.id,
      approved: cmd === 'approve',
      approver: values.approver ?? 'cli-user',
      reason: values.reason,
      pendingDir: values['pending-dir'] ?? podPath('pending'),
    });
    return;
  }

  if (cmd === 'pending') {
    cmdPending(values['pending-dir'] ?? podPath('pending'));
    return;
  }

  if (cmd === 'record') {
    if (!values.config || !values.server) {
      console.error('pod record requires --config <mcp-manager.json> --server <name>');
      console.error(usage());
      process.exit(1);
    }
    await cmdRecord({
      config: values.config,
      server: values.server,
      agent: values.agent ?? 'local',
      policy: values.policy,
      auditDir: values['audit-dir'] ?? podPath('audit'),
    });
    return;
  }

  if (cmd === 'audit') {
    await cmdAudit({
      server: values.server,
      tail: values.tail ? Number.parseInt(values.tail, 10) : 20,
      auditDir: values['audit-dir'] ?? podPath('audit'),
    });
    return;
  }

  if (cmd === 'sync') {
    if (!values['api-url'] && !values['agent-id'] && !values['sync-token'] && !values.config) {
      // 允许全部走默认 ~/.pod/cloud.json
    }
    const result = await runSync({
      config: values.config,
      auditDir: values['audit-dir'] ?? podPath('audit'),
      apiUrl: values['api-url'],
      agentId: values['agent-id'] ? Number.parseInt(values['agent-id'], 10) : undefined,
      syncToken: values['sync-token'],
    });
    if (result.total_synced === 0) log('nothing to sync');
    for (const srv of result.servers) log(`synced ${srv.synced} events from "${srv.server}"`);
    for (const b of result.bindings) log(`total synced: ${b.synced} (agent #${b.agent_id})`);
    return;
  }

  if (cmd === 'timeline') {
    cmdTimeline({
      auditDir: values['audit-dir'] ?? podPath('audit'),
      server: values.server,
      agent: values.agent,
      tool: values.tool,
      since: values.since,
      limit: values.limit ? Number.parseInt(values.limit, 10) : undefined,
    });
    return;
  }

  if (cmd === 'verify-audit') {
    cmdVerifyAudit(values['audit-dir'] ?? podPath('audit'), values.out);
    return;
  }

  if (cmd === 'export-evidence') {
    cmdExportEvidence(
      values['audit-dir'] ?? podPath('audit'),
      values['policy-dir'] ?? podPath('policies'),
      values.out ?? podPath('evidence', `pod-evidence-${new Date().toISOString().slice(0, 10)}.json`),
    );
    return;
  }

  if (cmd === 'verify-evidence') {
    if (!values.out) {
      console.error('pod verify-evidence requires --out <bundle.json>');
      process.exit(1);
    }
    cmdVerifyEvidence(values.out);
    return;
  }

  if (cmd === 'lint') {
    if (!values.policy) {
      console.error('pod lint requires --policy <file>');
      process.exit(1);
    }
    cmdLint(values.policy);
    return;
  }

  if (cmd === 'doctor') {
    cmdDoctor(values.policy);
    return;
  }

  if (cmd === 'pull-policy') {
    const result = await pullPolicies({
      config: values.config,
      apiUrl: values['api-url'],
      agentId: values['agent-id'] ? Number.parseInt(values['agent-id'], 10) : undefined,
      syncToken: values['sync-token'],
      outDir: values['out-dir'] ?? podPath('policies'),
    });
    if (result.policies.length === 0) log('云端无策略（可先在 Pod Cloud 策略中心创建模板或绑定本 agent）');
    for (const p of result.policies) {
      log(`pulled "${p.name}" v${p.version}${p.agent_id ? ` (agent #${p.agent_id})` : ' (template)'} -> ${p.path}`);
    }
    log(`use: pod serve --policy <path> 加载策略`);
    return;
  }

  if (cmd === 'scan') {
    cmdScan(values.json ?? false);
    return;
  }

  console.error(`unknown command: ${cmd}`);
  console.error(usage());
  process.exit(1);
}

/**
 * parseArgs 不允许选项值以 '-' 开头（如 --arg --import 会被判为 ambiguous），
 * 这里把裸 `--arg <v>` 重写为 `--arg=<v>`，两种写法都可用。
 */
function normalizePodArgs(argv: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i]!;
    if (tok === '--arg' && i + 1 < argv.length) {
      out.push(`--arg=${argv[i + 1]!}`);
      i++;
    } else {
      out.push(tok);
    }
  }
  return out;
}

function usage(): string {
  return `pod — AI agent security pod (Phase 0 scaffold)

Usage:
  pod init [--template baseline|record]
  pod serve --agent <name> --server <name> --policy <file> \\
           --command <cmd> [--arg <value> ...] [--audit-dir <dir>] \\
           [--approval-timeout <sec>] [--pending-dir <dir>] [--alert-config <file>] \
           [--transport stdio|http] [--port <n>]
  pod record --config <mcp-manager.json> --server <name> \\
             [--agent <name>] [--policy <file>] [--audit-dir <dir>]
  pod approve --id <approval-id> [--reason <why>] [--approver <who>]
  pod deny --id <approval-id> [--reason <why>] [--approver <who>]
  pod pending [--pending-dir <dir>]
  pod audit [--server <name>] [--tail <n>] [--audit-dir <dir>]
  pod timeline [--server <name>] [--agent <name>] [--tool <name>] [--since 2h|24h|7d] [--limit <n>]
  pod verify-audit [--audit-dir <dir>] [--out <report.md>]
  pod export-evidence [--audit-dir <dir>] [--policy-dir <dir>] [--out <bundle.json>]
  pod verify-evidence --out <bundle.json>
  pod lint --policy <file>
  pod doctor [--policy <file>]
  pod sync [--config <cloud.json>] [--api-url <url>] [--agent-id <n>] [--sync-token <t>] [--audit-dir <dir>]
  pod pull-policy [--config <cloud.json>] [--api-url <url>] [--agent-id <n>] [--sync-token <t>] [--out-dir <dir>]
  pod scan [--json]
  pod --help

record: 只录不拦模式（Phase 0 语料采集），从 dsh-mcp-manager 配置包装真实 MCP server。
approve/deny/pending: 审批旁路通道（stdio 被 MCP 占用，交互在另一个终端进行）。
audit:  查看审计（含哈希链校验）。
`;
}

main().catch((err: unknown) => {
  log(`fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
  process.exit(1);
});
