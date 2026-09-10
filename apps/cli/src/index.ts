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
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { AuditLog, appendToAuditFile, hashValue, loadAuditFile, type AuditEntry } from '@podsec/audit';
import type { Policy } from '@podsec/policy';
import { capabilityMapFromGraph, type CapabilityGraph } from '@podsec/graph';
import { createStdioProxy, createHttpProxy } from '@podsec/gateway';
import { scanMachine, renderMarkdown } from '@podsec/scan';
import { lintPolicy } from '@podsec/policy';
import { createFileApprovalProvider, decideApproval, listPendingApprovals } from './approval.js';
import { diffPolicies, draftPolicy, renderPolicyDiff } from './policy-draft.js';
import { applyOnboard, computeCoverage, discoverTargets, revertOnboard } from './onboard.js';
import { notifyApproval } from './notify.js';
import { watchPending } from './watch.js';
import { buildDigest, renderDigest } from './digest.js';
import { collectPathCandidates, createSnapshot, listSnapshots, restoreSnapshot } from './snapshot.js';
import { runSync, pullPolicies } from './sync.js';
import {
  buildTimeline,
  renderTimeline,
  verifyAll,
  renderVerifyReport,
  exportEvidence,
  renderEvidenceReport,
  verifyEvidenceBundle,
  loadAllAuditFiles,
  listAuditFiles,
  parseSince,
  type TimelineOptions,
} from './evidence.js';
import { loadAlertConfig, createAlertChecker, type AlertEvent } from './alert.js';
import { cmdGraphApply, cmdGraphBuild, cmdGraphExplain, cmdGraphToxic } from './graph/commands.js';
import { graphDir } from './graph/io.js';

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
        // P2：未知格式密钥兜底（hex 哈希熵上限 4.0，不会被误伤）
        entropy: { enabled: true, min_length: 24, threshold: 4.5, block: true },
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
    entropy: { enabled: true, min_length: 24, threshold: 4.5, block: true },
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
  /** record-only：策略照常求值并写审计（enforced:false），但一律放行（Phase 0 采集） */
  recordOnly?: boolean;
  /** 会话内记忆：同一 (server, tool) 批准过一次后本进程免重复审批 */
  rememberApprovals?: boolean;
  /** P2：approve 决策转发前对参数中的路径做快照 */
  snapshot?: boolean;
  /** P2：对 allow 决策也做快照（默认只快照 approve） */
  snapshotAll?: boolean;
  snapshotDir?: string;
  /** P2：HTTP 网关身份令牌（防止本机其他进程冒充 agent 连接） */
  authToken?: string;
  /** capabilityRules 使用的能力图路径（默认 ~/.pod/graph/potential.json） */
  graphPath?: string;
}

async function cmdServe(opts: ServeOptions): Promise<void> {
  const policy = JSON.parse(readFileSync(opts.policy, 'utf8')) as Policy;
  if (policy.capabilityRules) {
    const graphPath = opts.graphPath ?? podPath('graph', 'potential.json');
    if (existsSync(graphPath)) {
      try {
        const graph = JSON.parse(readFileSync(graphPath, 'utf8')) as CapabilityGraph;
        const map = capabilityMapFromGraph(graph);
        // 策略里显式声明的映射优先；图只补缺
        policy.capabilityMap = { ...map, ...(policy.capabilityMap ?? {}) };
        log(`capabilityRules: 从 ${graphPath} 加载 ${Object.keys(map).length} 个工具的能力映射`);
      } catch (err) {
        log(
          `⚠️ capabilityRules 已配置，但读取 ${graphPath} 失败：${err instanceof Error ? err.message : String(err)}；能力规则可能不生效`,
        );
      }
    } else {
      log(`⚠️ capabilityRules 已配置，但找不到 ${graphPath}；先运行 pod graph build 或 pod graph apply`);
    }
  }

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
      notifyApproval({ id: req.id, server: req.server, tool: req.tool, agent: req.agent });
    },
  });

  const snapshotDir = opts.snapshotDir ?? podPath('snapshots');
  const onBeforeForward = opts.snapshot
    ? async ({ tool, args, decision }: { tool: string; args: unknown; decision: 'allow' | 'approve' }) => {
        if (!opts.snapshotAll && decision !== 'approve') return;
        const paths = collectPathCandidates(args);
        if (paths.length === 0) return;
        const id = `${opts.server}-${Date.now()}-${randomUUID().slice(0, 6)}`;
        const manifest = createSnapshot(paths, { dir: snapshotDir, id, server: opts.server, tool });
        log(
          `SNAPSHOT #${id}: ${manifest.entries.length} 个路径已保存` +
            `${manifest.skipped.length > 0 ? `（跳过 ${manifest.skipped.length} 个）` : ''}`,
        );
        log(`  回滚: pod rollback --id ${id} --snapshot-dir ${snapshotDir}`);
        return { snapshotId: id };
      }
    : undefined;

  const server = await createStdioProxy({
    agent: opts.agent,
    serverName: opts.server,
    policy,
    audit,
    approval,
    recordOnly: opts.recordOnly,
    rememberApprovals: opts.rememberApprovals,
    onBeforeForward,
    command: opts.command,
    args: opts.args,
    // 透传网关进程环境：onboard 包装后，原 server 的 env 由 agent 传给 pod，
    // 再由这里传给真实 upstream（否则自定义 API key 会丢）。
    env: { ...process.env } as Record<string, string>,
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
      recordOnly: opts.recordOnly,
      rememberApprovals: opts.rememberApprovals,
      onBeforeForward,
      command: opts.command,
      args: opts.args,
      env: { ...process.env } as Record<string, string>,
      port: opts.port,
      host: '127.0.0.1',
      authToken: opts.authToken,
      log,
    });
    if (!opts.authToken) {
      log('⚠️ HTTP 网关未设置 --auth-token：本机任意进程都可连接（建议设置）');
    }
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
  const files = listAuditFiles(opts.auditDir);
  if (files.length === 0) {
    log(`no audit files in ${opts.auditDir}`);
    return;
  }
  const matched = opts.server
    ? files.filter((f) => f.key === opts.server || f.key.endsWith(`/${opts.server}`))
    : files;
  if (opts.server && matched.length === 0) {
    log(`no audit file for server "${opts.server}" in ${opts.auditDir} (have: ${files.map((f) => f.key).join(', ')})`);
    return;
  }
  for (const { key, path } of matched) {
    const log_ = loadAuditFile(path, ''); // 校验链（policyVersion 仅用于构造，不影响校验）
    const entries = log_.entries.slice(-opts.tail);
    log(`${key}.jsonl: ${log_.entries.length} entries (chain verified, last ${entries.length})`);
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
  // 防绕过检查（T 边界完整性）：用 onboard 的精确解析替代 scan 的启发式字符串匹配
  const coverage = computeCoverage(discoverTargets({ home: homedir() }));
  if (coverage.unmanaged.length === 0) {
    log(`✅ 未发现绕过网关的 MCP server（受管 ${coverage.managed.length} 个）`);
  } else {
    log(`⚠️ ${coverage.unmanaged.length} 个 MCP server 未经过 pod 网关（agent 可直连绕过策略/审计）:`);
    for (const b of coverage.unmanaged) log(`   - ${b.configPath} → "${b.server}" (${b.command})`);
    log('   修复: pod onboard --yes（或先 pod onboard 看计划）');
  }
  if (coverage.unsupported.length > 0) {
    log(`ℹ️ ${coverage.unsupported.length} 个 server 因非 stdio transport 暂不支持包装`);
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

function cmdExportEvidence(auditDir: string, policyDir: string, outPath: string, reportPath?: string): void {
  const bundle = exportEvidence({ auditDir, policyDir, outPath });
  log(`证据包已导出: ${outPath}`);
  log(`  审计文件: ${Object.keys(bundle.audits).length} 个 | 策略快照: ${Object.keys(bundle.policies).length} 个`);
  log(`  顶层哈希: ${bundle.top_level_hash.slice(0, 16)}…`);
  const report = reportPath ?? `${outPath}.md`;
  mkdirSync(dirname(report), { recursive: true });
  writeFileSync(report, renderEvidenceReport(bundle), 'utf8');
  log(`  一页式报告: ${report}`);
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

interface DigestCliOptions {
  auditDir: string;
  since: string;
  out?: string;
  json: boolean;
}

/** pod digest：本地安全周报（只读审计 + 覆盖率 + 哈希链健康） */
function cmdDigest(opts: DigestCliOptions): void {
  const files = loadAllAuditFiles(opts.auditDir);
  const input = files.map((f) => ({ server: f.server, entries: f.log.entries }));
  const from = parseSince(opts.since) ?? parseSince('7d')!;
  const to = new Date().toISOString();
  const chain = verifyAll(opts.auditDir).map((r) => ({ server: r.server, ok: r.ok, entries: r.entries }));
  const coverage = computeCoverage(discoverTargets({ home: homedir() }));
  const digest = buildDigest(input, {
    from,
    to,
    chain,
    coverage: {
      managed: coverage.managed.map((m) => m.server),
      unmanaged: coverage.unmanaged.map((m) => m.server),
    },
  });
  const text = opts.json ? JSON.stringify(digest, null, 2) : renderDigest(digest);
  if (opts.out) {
    mkdirSync(dirname(opts.out), { recursive: true });
    writeFileSync(opts.out, text + '\n', 'utf8');
    log(`周报已写入: ${opts.out}`);
  }
  process.stdout.write(text + '\n');
}

interface CoverageCliOptions {
  home: string;
  json: boolean;
  strict: boolean;
}

/** pod coverage：受管覆盖率 + 漂移检查（可配 launchd/cron 定时跑，--strict 用退出码告警） */
function cmdCoverage(opts: CoverageCliOptions): void {
  const coverage = computeCoverage(discoverTargets({ home: opts.home }));
  if (opts.json) {
    process.stdout.write(JSON.stringify(coverage, null, 2) + '\n');
  } else {
    const lines: string[] = ['# pod 受管覆盖率', ''];
    lines.push(`- 已受管：${coverage.managed.length} 个`);
    lines.push(`- 未受管：${coverage.unmanaged.length} 个（可绕过策略/审计）`);
    lines.push(`- 不支持包装：${coverage.unsupported.length} 个（非 stdio transport）`);
    lines.push('');
    if (coverage.unmanaged.length > 0) {
      lines.push('## 未受管 MCP server');
      lines.push('');
      lines.push('| server | agent | 命令 | 配置 |');
      lines.push('|--------|-------|------|------|');
      for (const u of coverage.unmanaged) {
        lines.push(`| ${u.server} | ${u.agent} | ${u.command} | ${u.configPath} |`);
      }
      lines.push('');
      lines.push('修复：`pod onboard --yes` 接管，或 `pod onboard` 先看计划。');
      lines.push('');
    }
    if (coverage.unsupported.length > 0) {
      lines.push('## 无法包装（v0 只支持 stdio）');
      lines.push('');
      for (const u of coverage.unsupported) lines.push(`- ${u.server}（${u.transport}）→ ${u.configPath}`);
      lines.push('');
    }
    lines.push('---');
    lines.push('pod coverage 只读配置，不修改任何文件。');
    lines.push('');
    process.stdout.write(lines.join('\n'));
  }
  if (opts.strict && coverage.unmanaged.length > 0) process.exitCode = 1;
}

function cmdSnapshots(dir: string, limit: number): void {
  const list = listSnapshots(dir);
  if (list.length === 0) {
    log(`no snapshots in ${dir}`);
    return;
  }
  log(`${list.length} snapshot(s) in ${dir} (last ${Math.min(limit, list.length)}):`);
  for (const s of list.slice(0, limit)) {
    log(
      `  ${s.id}  ${s.created_at}  ${s.server}.${s.tool}  ${s.entries.length} path(s)` +
        `${s.skipped.length > 0 ? ` (skipped ${s.skipped.length})` : ''}`,
    );
  }
}

function cmdRollback(dir: string, id: string): void {
  const { restored, missing } = restoreSnapshot(dir, id);
  log(`rollback ${id}: restored ${restored.length} path(s)`);
  for (const p of restored) log(`  ✅ ${p}`);
  for (const p of missing) log(`  ⚠️ missing in snapshot: ${p}`);
  if (restored.length === 0) process.exitCode = 1;
}

interface IngestOptions {
  agent: string;
  server: string;
  tool: string;
  decision: 'allow' | 'deny' | 'approve';
  outcome: 'ok' | 'error' | 'blocked';
  reason?: string;
  args?: string;
  session?: string;
  auditDir: string;
}

/**
 * pod ingest：把外部 agent 的事件（如 Codex PostToolUse hook）追加进本地哈希链。
 * 用于无法走 MCP 网关的 agent（Codex 内置 shell/exec 工具），让它们的活动也能上云。
 */
function cmdIngest(opts: IngestOptions): void {
  let args: unknown;
  if (opts.args) {
    try {
      args = JSON.parse(opts.args);
    } catch {
      args = opts.args;
    }
  }
  const path = join(opts.auditDir, opts.agent, `${opts.server}.jsonl`);
  mkdirSync(dirname(path), { recursive: true });
  const onAppend = (entry: AuditEntry): void => appendToAuditFile(path, entry);
  const auditLog = existsSync(path)
    ? loadAuditFile(path, 'external', { onAppend })
    : new AuditLog('external', { onAppend });
  const entry = auditLog.append({
    agent: opts.agent,
    session: opts.session ?? 'external',
    server: opts.server,
    tool: opts.tool,
    argsHash: hashValue(args),
    decision: opts.decision,
    outcome: opts.outcome,
    reason: opts.reason,
    policyVersion: 'external',
  });
  log(`ingested #${entry.seq} ${opts.agent}/${opts.server}.${opts.tool} (${opts.decision}/${opts.outcome})`);
}

function mostCommonAgent(input: Array<{ entries: AuditEntry[] }>): string | undefined {
  const counts = new Map<string, number>();
  for (const { entries } of input) {
    for (const e of entries) counts.set(e.agent, (counts.get(e.agent) ?? 0) + 1);
  }
  let best: string | undefined;
  let max = 0;
  for (const [agent, n] of counts) {
    if (n > max) {
      max = n;
      best = agent;
    }
  }
  return best;
}

interface PolicyDraftOptions {
  auditDir: string;
  agent?: string;
  server?: string;
  out: string;
  version?: string;
  /** 可选：与基线策略对比，输出"草稿到底改了什么" */
  diff?: string;
}

/** pod policy draft：从录制语料生成最小权限策略草稿（不自动启用） */
function cmdPolicyDraft(opts: PolicyDraftOptions): void {
  // server 名必须取审计条目里的 e.server，而不是文件路径 key：
  // pod ingest 的目录布局是 <auditDir>/<agent>/<server>.jsonl，
  // 用路径 key 会生成 "agent/server" 这种错误的策略 server 名。
  const byServer = new Map<string, AuditEntry[]>();
  for (const file of loadAllAuditFiles(opts.auditDir)) {
    for (const e of file.log.entries) {
      if (opts.server && e.server !== opts.server) continue;
      const list = byServer.get(e.server);
      if (list) list.push(e);
      else byServer.set(e.server, [e]);
    }
  }
  const input = [...byServer.entries()].map(([server, entries]) => ({ server, entries }));
  if (input.length === 0) {
    log(`no audit records in ${opts.auditDir}${opts.server ? ` for server "${opts.server}"` : ''}`);
    log('先采集语料: pod record --config <mcp-manager.json> --server <name>');
    process.exitCode = 1;
    return;
  }
  const agent = opts.agent ?? mostCommonAgent(input) ?? 'local';
  const summary = draftPolicy(input, { agent, version: opts.version });
  mkdirSync(dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, JSON.stringify(summary.policy, null, 2) + '\n', 'utf8');
  process.stdout.write(summary.report + '\n');
  if (opts.diff) {
    if (!existsSync(opts.diff)) {
      log(`diff baseline not found: ${opts.diff}`);
      process.exitCode = 1;
    } else {
      try {
        const baseline = JSON.parse(readFileSync(opts.diff, 'utf8')) as Policy;
        process.stdout.write('\n' + renderPolicyDiff(diffPolicies(baseline, summary.policy)) + '\n');
      } catch (err) {
        log(`diff baseline parse error: ${err instanceof Error ? err.message : String(err)}`);
        process.exitCode = 1;
      }
    }
  }
  log(`草稿已写入: ${opts.out}`);
  if (summary.issues.length > 0) {
    log('lint 提示:');
    for (const i of summary.issues) log(`  [${i.severity}] ${i.where}: ${i.message}`);
  }
}

interface OnboardOptions {
  home: string;
  config?: string;
  agent?: string;
  policyDir: string;
  dryRun: boolean;
  revert: boolean;
  podBin?: string;
}

/** pod onboard：发现本机 MCP server，默认 dry-run，--yes 才改写配置 */
function cmdOnboard(opts: OnboardOptions): void {
  if (opts.revert) {
    const restored = revertOnboard({ home: opts.home, config: opts.config });
    if (restored.length === 0) {
      log('没有可恢复的 pod 备份');
      return;
    }
    for (const r of restored) log(`已恢复 ${r.configPath} ← ${r.backup}`);
    return;
  }
  const targets = discoverTargets({ home: opts.home, config: opts.config, agent: opts.agent });
  if (targets.length === 0) {
    log('未发现可接管的 MCP 配置（支持 ~/.dsh/mcp-manager.json / ~/.claude.json / ~/.cursor/mcp.json）');
    return;
  }
  const result = applyOnboard(targets, {
    policyDir: opts.policyDir,
    dryRun: opts.dryRun,
    podBin: opts.podBin,
  });
  log(opts.dryRun ? 'pod onboard — 计划（dry-run，未修改任何文件）' : 'pod onboard — 已接管');
  for (const t of targets) {
    log(`  ${t.configPath} (agent=${t.agent})`);
    for (const s of t.servers) {
      const action = s.wrapped
        ? '已由 pod 包装，跳过'
        : s.transport && s.transport !== 'stdio'
          ? `transport=${s.transport}，v0 只支持 stdio，跳过`
          : '将包装为 pod serve --record-only';
      log(`    - ${s.name}: ${action}`);
    }
  }
  for (const p of result.policies) log(`  策略: ${p}${opts.dryRun ? '（dry-run 未写入）' : ''}`);
  for (const s of result.skipped) log(`  跳过: ${s}`);
  if (opts.dryRun) {
    log('确认无误后执行: pod onboard --yes');
  } else {
    log('下一步: 正常使用 agent 采集语料 → pod policy draft → 复核后切换执法模式');
    log('回滚: pod onboard --revert');
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
      home: { type: 'string' },
      'no-exec': { type: 'boolean' },
      timeout: { type: 'string' },
      graph: { type: 'string' },
      'cross-agent': { type: 'boolean' },
      'no-cross-agent': { type: 'boolean' },
      'min-confidence': { type: 'string' },
      'max-paths': { type: 'string' },
      'alert-config': { type: 'string' },
      tool: { type: 'string' },
      decision: { type: 'string' },
      outcome: { type: 'string' },
      args: { type: 'string' },
      session: { type: 'string' },
      since: { type: 'string' },
      limit: { type: 'string' },
      out: { type: 'string' },
      report: { type: 'string' },
      'policy-dir': { type: 'string' },
      diff: { type: 'string' },
      template: { type: 'string' },
      version: { type: 'string' },
      transport: { type: 'string' },
      port: { type: 'string' },
      'record-only': { type: 'boolean' },
      'remember-approvals': { type: 'boolean' },
      snapshot: { type: 'boolean' },
      'snapshot-all': { type: 'boolean' },
      'snapshot-dir': { type: 'string' },
      'auth-token': { type: 'string' },
      interval: { type: 'string' },
      once: { type: 'boolean' },
      'pod-bin': { type: 'string' },
      strict: { type: 'boolean' },
      yes: { type: 'boolean', short: 'y' },
      revert: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  const cmd = positionals[0];
  if (values.help) {
    console.error(usage());
    process.exit(0);
  }
  if (!cmd) {
    console.error(usage());
    process.exit(1);
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
      recordOnly: values['record-only'] === true,
      rememberApprovals: values['remember-approvals'] === true,
      snapshot: values.snapshot === true || values['snapshot-all'] === true,
      snapshotAll: values['snapshot-all'] === true,
      snapshotDir: values['snapshot-dir'],
      authToken: values['auth-token'] ?? process.env.POD_AUTH_TOKEN,
      graphPath: values.graph,
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

  if (cmd === 'watch') {
    await watchPending({
      pendingDir: values['pending-dir'] ?? podPath('pending'),
      intervalMs: values.interval ? Number.parseInt(values.interval, 10) : 1000,
      once: values.once === true,
      approver: values.approver ?? 'cli-user',
      interactive: process.stdin.isTTY === true && values.once !== true,
      log,
    });
    return;
  }

  if (cmd === 'snapshots') {
    cmdSnapshots(
      values['snapshot-dir'] ?? podPath('snapshots'),
      values.limit ? Number.parseInt(values.limit, 10) : 20,
    );
    return;
  }

  if (cmd === 'ingest') {
    if (!values.agent || !values.server || !values.tool) {
      console.error('pod ingest requires --agent --server --tool');
      process.exit(1);
    }
    cmdIngest({
      agent: values.agent,
      server: values.server,
      tool: values.tool,
      decision: (values.decision as 'allow' | 'deny' | 'approve') ?? 'allow',
      outcome: (values.outcome as 'ok' | 'error' | 'blocked') ?? 'ok',
      reason: values.reason,
      args: values.args,
      session: values.session,
      auditDir: values['audit-dir'] ?? podPath('audit'),
    });
    return;
  }

  if (cmd === 'rollback') {
    if (!values.id) {
      console.error('pod rollback requires --id <snapshot-id>');
      console.error(usage());
      process.exit(1);
    }
    cmdRollback(values['snapshot-dir'] ?? podPath('snapshots'), values.id);
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
      values.report,
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

  if (cmd === 'digest') {
    cmdDigest({
      auditDir: values['audit-dir'] ?? podPath('audit'),
      since: values.since ?? '7d',
      out: values.out,
      json: values.json ?? false,
    });
    return;
  }

  if (cmd === 'coverage') {
    cmdCoverage({ home: homedir(), json: values.json ?? false, strict: values.strict === true });
    return;
  }

  if (cmd === 'policy') {
    const sub = positionals[1];
    if (sub === 'draft') {
      cmdPolicyDraft({
        auditDir: values['audit-dir'] ?? podPath('audit'),
        agent: values.agent,
        server: values.server,
        out: values.out ?? podPath('policies', 'draft.json'),
        version: values.version,
        diff: values.diff,
      });
      return;
    }
    console.error(`unknown policy subcommand: ${sub ?? '(none)'} (available: draft)`);
    console.error(usage());
    process.exit(1);
  }

  if (cmd === 'graph') {
    const sub = positionals[1];
    const home = values.home ?? homedir();
    const outDir = values['out-dir'] ?? graphDir(home);
    if (sub === 'build') {
      const code = await cmdGraphBuild({
        home,
        config: values.config,
        noExec: values['no-exec'] === true,
        timeoutMs: Number.parseInt(values.timeout ?? '10000', 10),
        out: values.out ?? join(outDir, 'potential.json'),
        policyPath: values.policy,
        json: values.json === true,
      });
      process.exit(code);
    }
    if (sub === 'toxic') {
      const code = cmdGraphToxic({
        graphPath: values.graph ?? join(outDir, 'potential.json'),
        outDir,
        // 默认开启跨 agent：dogfood 中最有价值的发现来自跨 agent 组合
        crossAgent: values['no-cross-agent'] !== true,
        minConfidence: Number.parseFloat(values['min-confidence'] ?? '0.5'),
        maxPaths: Number.parseInt(values['max-paths'] ?? '20', 10),
        baselinePath: values.diff,
        json: values.json === true,
      });
      process.exit(code);
    }
    if (sub === 'explain') {
      const id = positionals[2];
      if (!id) {
        console.error('pod graph explain requires <path-id>');
        process.exit(1);
      }
      process.exit(cmdGraphExplain({ pathsPath: join(outDir, 'paths.json'), id, json: values.json === true }));
    }
    if (sub === 'apply') {
      if (!values.policy) {
        console.error('pod graph apply requires --policy <file>');
        process.exit(1);
      }
      const out = values.out ?? values.policy.replace(/\.json$/, '') + '.with-capabilities.json';
      process.exit(
        cmdGraphApply({
          graphPath: values.graph ?? join(outDir, 'potential.json'),
          policyPath: values.policy,
          out,
          json: values.json === true,
        }),
      );
    }
    console.error(`unknown graph subcommand: ${sub ?? '(none)'} (available: build, toxic, explain, apply)`);
    process.exit(1);
  }

  if (cmd === 'onboard') {
    cmdOnboard({
      home: homedir(),
      config: values.config,
      agent: values.agent,
      policyDir: values['policy-dir'] ?? podPath('policies'),
      dryRun: values.yes !== true,
      revert: values.revert === true,
      podBin: values['pod-bin'],
    });
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
           [--transport stdio|http] [--port <n>] [--record-only] [--remember-approvals] \
           [--snapshot] [--snapshot-all] [--snapshot-dir <dir>] [--auth-token <token>]
  pod record --config <mcp-manager.json> --server <name> \\
             [--agent <name>] [--policy <file>] [--audit-dir <dir>]
  pod approve --id <approval-id> [--reason <why>] [--approver <who>]
  pod deny --id <approval-id> [--reason <why>] [--approver <who>]
  pod pending [--pending-dir <dir>]
  pod watch [--pending-dir <dir>] [--interval <ms>] [--once] [--approver <who>]
  pod snapshots [--snapshot-dir <dir>] [--limit <n>]
  pod rollback --id <snapshot-id> [--snapshot-dir <dir>]
  pod ingest --agent <name> --server <name> --tool <name> \\
             [--decision allow|deny|approve] [--outcome ok|error|blocked] \\
             [--args <json>] [--reason <text>] [--session <id>] [--audit-dir <dir>]
  pod audit [--server <name>] [--tail <n>] [--audit-dir <dir>]
  pod timeline [--server <name>] [--agent <name>] [--tool <name>] [--since 2h|24h|7d] [--limit <n>]
  pod verify-audit [--audit-dir <dir>] [--out <report.md>]
  pod export-evidence [--audit-dir <dir>] [--policy-dir <dir>] [--out <bundle.json>] [--report <report.md>]
  pod verify-evidence --out <bundle.json>
  pod lint --policy <file>
  pod doctor [--policy <file>]
  pod sync [--config <cloud.json>] [--api-url <url>] [--agent-id <n>] [--sync-token <t>] [--audit-dir <dir>]
  pod pull-policy [--config <cloud.json>] [--api-url <url>] [--agent-id <n>] [--sync-token <t>] [--out-dir <dir>]
  pod policy draft [--audit-dir <dir>] [--agent <name>] [--server <name>] [--out <file>] [--diff <baseline.json>]
  pod onboard [--config <path>] [--agent <name>] [--policy-dir <dir>] [--pod-bin <path>] [--yes] [--revert]
  pod digest [--since 7d] [--audit-dir <dir>] [--out <file>] [--json]
  pod coverage [--json] [--strict]
  pod scan [--json]
  pod graph build [--home <dir>] [--config <path>] [--no-exec] [--timeout <ms>] [--out <file>] [--policy <file>] [--json]
  pod graph toxic [--graph <file>] [--out-dir <dir>] [--no-cross-agent] [--min-confidence <0-1>] [--max-paths <n>] [--diff <baseline.json>] [--json]
  pod graph explain <path-id|chain-id> [--out-dir <dir>] [--json]
  pod graph apply --policy <file> [--graph <file>] [--out <file>] [--json]
  pod --help

record: 只录不拦模式（Phase 0 语料采集），从 dsh-mcp-manager 配置包装真实 MCP server。
policy draft: 从录制语料生成最小权限策略草稿（只读审计，不自动启用）；--diff 对比基线策略，输出收紧/放宽清单。
onboard: 发现并接管本机 MCP server（默认 dry-run；--yes 改写，--revert 回滚）。
digest: 本地安全周报（只读审计 + 覆盖率 + 哈希链健康，不联网）。
coverage: 受管覆盖率与配置漂移检查（--strict 有未受管 server 时退出码 1）。
approve/deny/pending: 审批旁路通道（stdio 被 MCP 占用，交互在另一个终端进行）。
watch:  长驻审批队列：新请求立即提示，TTY 下可直接批准/拒绝。
snapshots/rollback: 高危写操作的快照与回滚（serve --snapshot 开启）。
ingest: 把外部 agent 事件（如 Codex PostToolUse hook）追加进本地哈希链。
audit:  查看审计（含哈希链校验）。
`;
}

main().catch((err: unknown) => {
  log(`fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
  process.exit(1);
});
