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
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import {
  AuditLog,
  ChainAppender,
  appendEntryExclusive,
  appendToAuditFile,
  hashValue,
  loadAuditFile,
  type AuditEntry,
} from '@podsec/audit';
import type { Policy } from '@podsec/policy';
import { capabilityMapFromGraph, type CapabilityGraph } from '@podsec/graph';
import { createStdioProxy, createHttpProxy } from '@podsec/gateway';
import { scanMachine, renderMarkdown } from '@podsec/scan';
import {
  DEFAULT_RULES,
  applyRulePack,
  buildRulePack,
  lintPolicy,
  parseRulePack,
  signRulePack,
  verifyRulePack,
  type RuleSetOverride,
  type SignedRulePack,
} from '@podsec/policy';
import { createFileApprovalProvider, decideApproval, listPendingApprovals } from './approval.js';
import { diffPolicies, draftPolicy, mostCommonAgent, renderPolicyDiff } from './policy-draft.js';
import { runHarden } from './harden.js';
import { runRedteam } from './redteam.js';
import { renderRedteamReport } from '@podsec/redteam';
import { signPolicy, verifyPolicy } from './policy-sign.js';
import { applyOnboard, computeCoverage, discoverTargets, revertOnboard } from './onboard.js';
import { notifyApproval } from './notify.js';
import { watchPending } from './watch.js';
import { buildDigest, renderDigest } from './digest.js';
import { collectPathCandidates, createSnapshot, listSnapshots, restoreSnapshot } from './snapshot.js';
import { runSync, pullPolicies, loadCloudConfig, uploadHardenReport } from './sync.js';
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
import {
  cmdGraphApply,
  cmdGraphBaseline,
  cmdGraphBuild,
  cmdGraphDiff,
  cmdGraphExplain,
  cmdGraphMark,
  cmdGraphObserve,
  cmdGraphRetention,
  cmdGraphToxic,
} from './graph/commands.js';
import { graphDir } from './graph/io.js';
import { recordUsage } from './graph/retention.js';
import { cmdUi } from './ui.js';
import { getLocale, normalizeLocale, setLocale, t, type Locale } from '@podsec/i18n';
import {
  appendControlEvent,
  buildTrace,
  delegateCheck,
  delegateIssue,
  delegateVerify,
  detectAnomalies,
  expandPath,
  freezePosture,
  grantIssue,
  grantList,
  identityInit,
  identityList,
  identityVerify,
  readBaseline,
  readQuarantineFile,
  resolveRules,
  runPosture,
  quarantineAdd,
  quarantineRemove,
} from './control-plane.js';
import type { RuleSet } from '@podsec/policy';

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

type ProxyServer = Awaited<ReturnType<typeof createStdioProxy>>;

/**
 * 连接 agent 侧的 stdio transport，并在 agent 消失时退出进程。
 *
 * 两个退出信号缺一不可：
 *   1. stdin EOF —— 正常情况，agent 关掉管道；
 *   2. PPID 迁移到 1 —— agent 进程被强杀、或管道写端被别的子进程继承时不会来 EOF，
 *      这时网关会被 launchd 收养并永久滞留（dogfood 机器上曾留下 5 个从 9/7 起就没有客户端的网关）。
 *      只在「启动时本来有父进程」时才判定，避免把经 wrapper 后台启动的网关误杀。
 */
async function connectStdioAndExitOnAgentGone(server: ProxyServer, label: string): Promise<void> {
  const { StdioServerTransport } = await import('@modelcontextprotocol/sdk/server/stdio.js');
  let closing = false;
  const shutdown = (reason: string): void => {
    if (closing) return;
    closing = true;
    log(t('{reason}，{label} 退出', { reason, label }));
    void server.close().catch(() => undefined);
    process.exit(0);
  };

  process.stdin.on('end', () => shutdown('agent 断开（stdin EOF）'));

  // ponytail: 只看「启动时父进程还在」的情况。若 agent 在网关起来之前就死了（tsx 启动约 1-2s），
  // 这里已经 ppid=1，看门狗不装，只能靠 stdin EOF 收敛。要覆盖这一档就得引入空闲超时。
  if (process.ppid !== 1) {
    setInterval(() => {
      if (process.ppid === 1) shutdown('agent 进程已退出（已 reparent 到 launchd）');
    }, 5000).unref();
  }

  await server.connect(new StdioServerTransport());
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
      log(t('未知模板 "{name}"，可用: {list}', { name: template, list: Object.keys(TEMPLATES).join(', ') }));
      return;
    } else {
      writeFileSync(policyFile, JSON.stringify(EXAMPLE_POLICY, null, 2) + '\n', 'utf8');
    }
  }
  log(`initialized ${POD_HOME}`);
  log(`policy: ${policyFile}`);
  // 规则文件是用户的：只在缺失时落一份默认值，之后 pod 不再覆盖它
  const rulesFile = podPath('rules.json');
  if (!existsSync(rulesFile)) {
    writeFileSync(rulesFile, JSON.stringify(DEFAULT_RULES, null, 2) + '\n', 'utf8');
    log(t('rules:  {path}（判定规则归你，改这里即改判定；写错会 fail-closed 报错）', { path: rulesFile }));
  } else {
    log(t('rules:  {path}（已存在，未覆盖）', { path: rulesFile }));
  }
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
  /** 控制平面规则（注入信号/工具元数据/egress/熔断/JIT），默认 ~/.pod/rules.json */
  rules?: RuleSet;
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
        log(t('capabilityRules: 从 {path} 加载 {n} 个工具的能力映射', { path: graphPath, n: Object.keys(map).length }));
      } catch (err) {
        log(
          t('⚠️ capabilityRules 已配置，但读取 {path} 失败：{err}；能力规则可能不生效', {
            path: graphPath,
            err: err instanceof Error ? err.message : String(err),
          }),
        );
      }
    } else {
      log(t('⚠️ capabilityRules 已配置，但找不到 {path}；先运行 pod graph build 或 pod graph apply', { path: graphPath }));
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
  // 跨进程锁：同一 agent+server 可能同时有 stdio 网关（随会话启动）与常驻 HTTP
  // 网关，两者写同一个文件。没有锁就会各自算出同一个 seq/prevHash，把链写分叉。
  const audit = new ChainAppender(auditPath, policy.version, {
    onAppend: (entry) => alertCheck?.(entry),
  });
  audit.preflight(); // 断链则拒绝启动，而不是往里写坏数据

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
        log(t('  回滚: {cmd}', { cmd: `pod rollback --id ${id} --snapshot-dir ${snapshotDir}` }));
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
    rules: opts.rules,
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
      rules: opts.rules,
      command: opts.command,
      args: opts.args,
      env: { ...process.env } as Record<string, string>,
      port: opts.port,
      host: '127.0.0.1',
      authToken: opts.authToken,
      log,
    });
    if (!opts.authToken) {
      log(t('⚠️ HTTP 网关未设置 --auth-token：本机任意进程都可连接（建议设置）'));
    }
    log(`gateway ready on ${result.url} (HTTP, resident)`);
    log('agent-side config: point your agent\'s MCP server at the URL above');
    return;
  }
  await connectStdioAndExitOnAgentGone(server, `gateway(${opts.server})`);
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
  const audit = new ChainAppender(auditPath, policy.version);
  audit.preflight();

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

  await connectStdioAndExitOnAgentGone(server, `recorder(${opts.server})`);
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
    log(t('✅ {path}: 策略检查通过（无问题）', { path: policyPath }));
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
  log(t('pod doctor — 环境与配置自检'));
  if (policyPath) {
    try {
      cmdLint(policyPath);
    } catch (e) {
      log(t('❌ 策略文件不可读: {error}', { error: e instanceof Error ? e.message : String(e) }));
      process.exitCode = 1;
    }
  }
  // 防绕过检查（T 边界完整性）：用 onboard 的精确解析替代 scan 的启发式字符串匹配
  const coverage = computeCoverage(discoverTargets({ home: homedir() }));
  if (coverage.unmanaged.length === 0) {
    log(t('✅ 未发现绕过网关的 MCP server（受管 {managed} 个）', { managed: coverage.managed.length }));
  } else {
    log(t('⚠️ {count} 个 MCP server 未经过 pod 网关（agent 可直连绕过策略/审计）:', { count: coverage.unmanaged.length }));
    for (const b of coverage.unmanaged) log(`   - ${b.configPath} → "${b.server}" (${b.command})`);
    log(t('   修复: pod onboard --yes（或先 pod onboard 看计划）'));
  }
  if (coverage.unsupported.length > 0) {
    log(t('ℹ️ {count} 个 server 因非 stdio transport 暂不支持包装', { count: coverage.unsupported.length }));
  }
  // 云配置
  const cloudPath = join(homedir(), '.pod', 'cloud.json');
  if (existsSync(cloudPath)) {
    try {
      const cfg = JSON.parse(readFileSync(cloudPath, 'utf8')) as { api_url?: string; agent_id?: number };
      log(`✅ cloud.json: api=${cfg.api_url} agent=${cfg.agent_id}`);
    } catch {
      log(t('❌ cloud.json 解析失败'));
    }
  } else {
    log(t('ℹ️ 未配置 cloud.json（pod sync/pull-policy 不可用，本地功能不受影响）'));
  }
  // 审计目录
  const auditDir = podPath('audit');
  log(
    existsSync(auditDir)
      ? t('✅ 审计目录: {path}', { path: auditDir })
      : t('ℹ️ 审计目录不存在（首次 record/serve 时创建）: {path}', { path: auditDir }),
  );
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
    log(t('自检报告已写入: {path}', { path: out }));
  }
  process.stdout.write(report + '\n');
  if (results.some((r) => !r.ok)) process.exitCode = 1;
}

function cmdExportEvidence(auditDir: string, policyDir: string, outPath: string, reportPath?: string): void {
  const bundle = exportEvidence({ auditDir, policyDir, outPath });
  log(t('证据包已导出: {path}', { path: outPath }));
  log(t('  审计文件: {files} 个 | 策略快照: {policies} 个', { files: Object.keys(bundle.audits).length, policies: Object.keys(bundle.policies).length }));
  log(t('  顶层哈希: {hash}', { hash: `${bundle.top_level_hash.slice(0, 16)}…` }));
  const report = reportPath ?? `${outPath}.md`;
  mkdirSync(dirname(report), { recursive: true });
  writeFileSync(report, renderEvidenceReport(bundle), 'utf8');
  log(t('  一页式报告: {path}', { path: report }));
  log(t('  验证: {cmd}', { cmd: `pod verify-evidence ${outPath}` }));
}

function cmdVerifyEvidence(path: string): void {
  const r = verifyEvidenceBundle(path);
  if (r.ok) log(t('✅ 证据包有效（顶层哈希匹配，未被修改）: {path}', { path }));
  else {
    log(t('❌ 证据包校验失败: {reason}', { reason: r.reason ?? '' }));
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
    log(t('周报已写入: {path}', { path: opts.out }));
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
    const lines: string[] = [t('# pod 受管覆盖率'), ''];
    lines.push(t('- 已受管：{n} 个', { n: coverage.managed.length }));
    lines.push(t('- 未受管：{n} 个（可绕过策略/审计）', { n: coverage.unmanaged.length }));
    lines.push(t('- 不支持包装：{n} 个（非 stdio transport）', { n: coverage.unsupported.length }));
    lines.push('');
    if (coverage.unmanaged.length > 0) {
      lines.push(t('## 未受管 MCP server'));
      lines.push('');
      lines.push(t('| server | agent | 命令 | 配置 |'));
      lines.push('|--------|-------|------|------|');
      for (const u of coverage.unmanaged) {
        lines.push(`| ${u.server} | ${u.agent} | ${u.command} | ${u.configPath} |`);
      }
      lines.push('');
      lines.push(t('修复：`pod onboard --yes` 接管，或 `pod onboard` 先看计划。'));
      lines.push('');
    }
    if (coverage.unsupported.length > 0) {
      lines.push(t('## 无法包装（v0 只支持 stdio）'));
      lines.push('');
      for (const u of coverage.unsupported) lines.push(`- ${u.server}（${u.transport}）→ ${u.configPath}`);
      lines.push('');
    }
    lines.push('---');
    lines.push(t('pod coverage 只读配置，不修改任何文件。'));
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
  // 跨进程锁：Codex PostToolUse 钩子并发触发时，多个 pod ingest 会同时追加
  // 同一个文件；没有锁就会算出相同的 seq/prevHash，把链写分叉（2026-09-09 事故）。
  const entry = appendEntryExclusive(path, 'external', () => ({
    agent: opts.agent,
    session: opts.session ?? 'external',
    server: opts.server,
    tool: opts.tool,
    argsHash: hashValue(args),
    decision: opts.decision,
    outcome: opts.outcome,
    reason: opts.reason,
    policyVersion: 'external',
  }));
  log(`ingested #${entry.seq} ${opts.agent}/${opts.server}.${opts.tool} (${opts.decision}/${opts.outcome})`);
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
    log(t('先采集语料: pod record --config <mcp-manager.json> --server <name>'));
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
  log(t('草稿已写入: {path}', { path: opts.out }));
  if (summary.issues.length > 0) {
    log(t('lint 提示:'));
    for (const i of summary.issues) log(`  [${i.severity}] ${i.where}: ${i.message}`);
  }
}

/**
 * 应用规则包（pod rules apply / pull 共用）。
 *
 * 写盘用"临时文件 + rename"而不是直接覆盖：rules.json 写坏会让
 * loadRules 抛错、整个 pod 进入 fail-closed——半截文件不能留在地上。
 */
function cmdRulesApply(input: {
  pack: SignedRulePack;
  rulesOverride?: string;
  auditDir: string;
  allowRelax: boolean;
  allowExpansion: boolean;
}): void {
  const target = input.rulesOverride ?? podPath('rules.json');
  const base = resolveRules(input.rulesOverride, POD_HOME);
  const { rules, changes, relaxations } = applyRulePack(base, input.pack, {
    allowRelax: input.allowRelax,
    allowExpansion: input.allowExpansion,
  });
  const tmp = `${target}.tmp`;
  writeFileSync(tmp, JSON.stringify(rules, null, 2) + '\n', 'utf8');
  renameSync(tmp, target);

  const tightened = changes.filter((c) => c.impact === 'tighten').length;
  const unknown = changes.length - tightened - relaxations.length;
  log(`规则包 ${input.pack.packVersion}（${input.pack.issuedBy}）已应用 → ${target}`);
  log(`  收紧 ${tightened} 项 · 放宽 ${relaxations.length} 项 · 方向待人工确认 ${unknown} 项`);
  // 带上具体内容：只说"injection.signals 少了一条"没法判断该不该放行
  for (const r of relaxations.slice(0, 5)) {
    const detail = r.from ?? r.to;
    log(`  ⚠️ 放宽：${r.where}（${r.kind}${detail ? `: ${detail}` : ''}）`);
  }

  // 配置变更进控制平面审计链（G1）——"这条规则是谁、什么时候换上的"必须可查
  try {
    appendControlEvent({
      auditDir: input.auditDir,
      agent: '_control',
      kind: 'config-change',
      tool: 'rules',
      reason: `rules-apply:${input.pack.issuedBy}@${input.pack.packVersion}:tighten=${tightened},relax=${relaxations.length}`,
      payload: {
        packVersion: input.pack.packVersion,
        issuedBy: input.pack.issuedBy,
        issuedAt: input.pack.issuedAt,
        target,
      },
    });
  } catch (err) {
    // 记不上账不等于应用失败，但绝不能静默——否则"看起来换上了、其实没进链"
    console.error(`⚠️ 规则已应用，但未能写入审计链：${err instanceof Error ? err.message : String(err)}`);
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
      log(t('没有可恢复的 pod 备份'));
      return;
    }
    for (const r of restored) log(t('已恢复 {config} ← {backup}', { config: r.configPath, backup: r.backup }));
    return;
  }
  const targets = discoverTargets({ home: opts.home, config: opts.config, agent: opts.agent });
  if (targets.length === 0) {
    log(t('未发现可接管的 MCP 配置（支持 ~/.dsh/mcp-manager.json / ~/.claude.json / ~/.cursor/mcp.json）'));
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
  for (const p of result.policies) log(t('  策略: {path}{dry}', { path: p, dry: opts.dryRun ? t('（dry-run 未写入）') : '' }));
  for (const s of result.skipped) log(t('  跳过: {item}', { item: s }));
  if (opts.dryRun) {
    log(t('确认无误后执行: pod onboard --yes'));
  } else {
    log(t('下一步: 正常使用 agent 采集语料 → pod policy draft → 复核后切换执法模式'));
    log(t('回滚: pod onboard --revert'));
  }
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    args: normalizePodArgs(process.argv.slice(2)),
    allowPositionals: true,
    options: {
      agent: { type: 'string' },
      // 输出语言：--lang en-US / zh-CN；也可以 POD_LANG / LANG 环境变量兜底
      lang: { type: 'string' },
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
      'policy-public-key': { type: 'string' },
      'require-signature': { type: 'boolean' },
      url: { type: 'string' },
      'allow-relax': { type: 'boolean' },
      'allow-expansion': { type: 'boolean' },
      'no-evidence': { type: 'boolean' },
      upload: { type: 'boolean' },
      scenarios: { type: 'string' },
      'export-surface': { type: 'string' },
      'from-cloud': { type: 'boolean' },
      llm: { type: 'boolean' },
      provider: { type: 'string' },
      model: { type: 'string' },
      'llm-base-url': { type: 'string' },
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
      in: { type: 'string' },
      key: { type: 'string' },
      sig: { type: 'string' },
      observed: { type: 'string' },
      'capability-diff': { type: 'string' },
      note: { type: 'string' },
      since: { type: 'string' },
      days: { type: 'string' },
      limit: { type: 'string' },
      out: { type: 'string' },
      report: { type: 'string' },
      'policy-dir': { type: 'string' },
      diff: { type: 'string' },
      template: { type: 'string' },
      version: { type: 'string' },
      rules: { type: 'string' },
      baseline: { type: 'string' },
      ttl: { type: 'string' },
      'single-use': { type: 'boolean' },
      capability: { type: 'string', multiple: true },
      parent: { type: 'string' },
      child: { type: 'string' },
      'parent-policy': { type: 'string' },
      'child-policy': { type: 'string' },
      'issued-by': { type: 'string' },
      'parent-token': { type: 'string' },
      audit: { type: 'boolean' },
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
  // 语言要在任何输出之前定下来（包括 --help）
  if (values.lang) {
    const parsed = normalizeLocale(values.lang);
    if (!parsed) {
      console.error(`Unknown language "${values.lang}"; supported: zh-CN, en-US`);
      process.exit(1);
    }
    setLocale(parsed);
  }
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
      rules: resolveRules(values.rules, POD_HOME),
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
    // 云端熔断收敛：这是"出事时不用 SSH 上机器"的那条通道
    for (const q of result.quarantine) {
      if (q.applied.length > 0) {
        log(`⛔ 云端下发熔断并已在本地生效（agent #${q.agent_id}）：${q.applied.join('、')}`);
      }
      if (q.released.length > 0) {
        log(`✅ 云端解除熔断（agent #${q.agent_id}）：${q.released.join('、')}`);
      }
      if (q.desired === true && q.applied.length === 0) {
        log(`⛔ 本地已处于熔断状态（agent #${q.agent_id}）`);
      }
      if (q.error) log(`⚠️ agent #${q.agent_id} 熔断状态未同步：${q.error}`);
    }
    // 逐项报失败但整体继续:一条死 token / 一条断链不该让整台机器停止上云。
    // 退出码仍置 1,让脚本与自动化能发现"没有全部成功"。
    for (const f of result.failures) {
      log(`✗ agent #${f.agent_id}${f.server ? ` server=${f.server}` : ''}: ${f.message}`);
    }
    if (result.failures.length > 0) {
      log(t('{count} 项失败，其余已照常同步；修好上面这些再跑一次 pod sync。', { count: result.failures.length }));
      process.exitCode = 1;
    }
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
      policyPublicKey: values['policy-public-key'],
      requireSignature: values['require-signature'] === true,
      outDir: values['out-dir'] ?? podPath('policies'),
    });
    if (result.policies.length === 0) log(t('云端无策略（可先在 Pod Cloud 策略中心创建模板或绑定本 agent）'));
    for (const p of result.policies) {
      log(`pulled "${p.name}" v${p.version}${p.agent_id ? ` (agent #${p.agent_id})` : ' (template)'} -> ${p.path}`);
    }
    log(t('use: pod serve --policy <path> 加载策略'));
    return;
  }

  if (cmd === 'scan') {
    cmdScan(values.json ?? false);
    return;
  }

  // ---------- 控制平面加固命令（docs/control-plane-hardening.md） ----------

  if (cmd === 'posture') {
    const rules = resolveRules(values.rules, POD_HOME);
    const auditDir = values['audit-dir'] ?? podPath('audit');
    const baselinePath = values.baseline ?? podPath('posture', 'baseline.json');
    if (positionals[1] === 'freeze') {
      const r = freezePosture({ rules, auditDir, baselinePath, home: homedir() });
      log(t('基线已写入 {path}', { path: r.baselinePath }));
      log(
        t('  冻结项 {configs} · 记忆 {memory} · 钩子 {hooks} · MCP 来源 {packages}', {
          configs: r.counts.configs,
          memory: r.counts.memory,
          hooks: r.counts.hooks,
          packages: r.counts.packages,
        }),
      );
      log(t('  之后任何变更都会在 pod posture 里报出来（规则决定严重级别）。'));
      return;
    }
    const run = runPosture({
      rules,
      auditDir,
      baselinePath,
      writeAudit: values.audit === true,
      strict: values.strict === true,
      home: homedir(),
    });
    process.stdout.write((values.json ? JSON.stringify(run.result, null, 2) : run.report) + '\n');
    if (run.exitCode !== 0) process.exitCode = run.exitCode;
    return;
  }

  // ---------- 加固审计交付（方向 A：一次性审计服务） ----------

  if (cmd === 'harden') {
    const result = runHarden({
      home: values.home ?? homedir(),
      auditDir: values['audit-dir'] ?? podPath('audit'),
      policyDir: values['policy-dir'] ?? podPath('policies'),
      baselinePath: values.baseline ?? podPath('posture', 'baseline.json'),
      rules: resolveRules(values.rules, POD_HOME),
      outDir: values.out ?? podPath('harden', new Date().toISOString().replace(/[:.]/g, '-')),
      agent: values.agent,
      server: values.server,
      includeEvidence: values['no-evidence'] !== true,
      writeAudit: values.audit === true,
    });
    if (values.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    } else {
      const s = result.summary;
      log(`加固审计报告已生成：${result.reportPath}`);
      log(`  🔴 high ${s.high} · 🟠 medium ${s.medium} · 🟡 low ${s.low}`);
      log(`  agent 平台 ${s.platforms.length} · MCP server ${s.mcpServers} · 疑似暴露密钥 ${s.exposedSecrets}`);
      log(
        `  审计链 ${s.auditChains} 条 / ${s.auditEntries} 条记录` +
          (s.brokenChains > 0 ? `（⚠️ ${s.brokenChains} 条断裂）` : ''),
      );
      if (s.baselineMissing) log('  ⚠️ 未建立姿态基线：漂移类检查未生效，建议先跑 pod posture freeze');
      log(`  交付目录：${result.outDir}`);
    }

    if (values.upload === true) {
      const cfg = loadCloudConfig(values.config);
      const syncToken = cfg.sync_token ?? cfg.agents?.[0]?.sync_token;
      if (!syncToken) {
        console.error(`云配置里没有 sync_token，无法上传（${values.config ?? '~/.pod/cloud.json'}）`);
        process.exit(1);
      }
      const findingsRaw = readFileSync(join(result.outDir, 'findings.json'), 'utf8');
      const { id } = await uploadHardenReport(
        { api_url: cfg.api_url, sync_token: syncToken },
        {
          generated_at: result.generatedAt,
          rules_version: result.summary.rulesVersion,
          high: result.summary.high,
          medium: result.summary.medium,
          low: result.summary.low,
          mcp_servers: result.summary.mcpServers,
          exposed_secrets: result.summary.exposedSecrets,
          broken_chains: result.summary.brokenChains,
          report_md: readFileSync(result.reportPath, 'utf8'),
          findings_json: findingsRaw,
        },
      );
      // 说清楚传了什么、没传什么——本地优先的承诺要能被验证，而不是靠信任
      log(`已上传到云端（报告 #${id}）：report.md + findings.json`);
      log('  未上传：evidence.json（原始审计链）——它在本地目录里，需要时你自己决定要不要给。');
    }
    return;
  }

  // ---------- 策略红队（大模型想攻击，网关判定器判结果） ----------

  if (cmd === 'redteam') {
    if (!values.policy) {
      console.error('pod redteam requires --policy <file>');
      console.error(usage());
      process.exit(1);
    }
    const outDir = values.out ?? podPath('redteam');
    try {
      const result = await runRedteam({
        policyPath: values.policy,
        rules: resolveRules(values.rules, POD_HOME),
        auditDir: values['audit-dir'] ?? podPath('audit'),
        podHome: POD_HOME,
        outDir,
        ...(values.scenarios ? { scenariosPath: values.scenarios } : {}),
        ...(values['export-surface'] ? { exportSurfacePath: values['export-surface'] } : {}),
        useLlm: values.llm === true,
        ...(values.provider ? { provider: values.provider } : {}),
        ...(values.model ? { model: values.model } : {}),
        ...(values['llm-base-url'] ? { baseUrl: values['llm-base-url'] } : {}),
        json: values.json === true,
        log,
      });
      if (values.json) {
        process.stdout.write(JSON.stringify(result.report, null, 2) + '\n');
      } else {
        process.stdout.write(renderRedteamReport(result.report) + '\n');
      }
      log(`红队报告已写入：${join(outDir, 'redteam-report.md')}`);
      // 高危绕过 → 退出码 1，便于挂 CI（与 pod posture --strict 同惯例）
      if (result.report.findings.some((f) => f.severity === 'high')) process.exitCode = 1;
      return;
    } catch (err) {
      console.error(`redteam 失败：${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    }
  }

  if (cmd === 'identity') {
    const rules = resolveRules(values.rules, POD_HOME);
    const dir = expandPath(rules.identity.dir);
    const auditDir = values['audit-dir'] ?? podPath('audit');
    const sub = positionals[1] ?? 'list';
    if (sub === 'init') {
      if (!values.agent) {
        console.error('pod identity init requires --agent <name>');
        process.exit(1);
      }
      const r = identityInit({ agent: values.agent, dir, auditDir });
      log(t('identity 已建立：{agent}', { agent: values.agent }));
      log(`  fingerprint: ${r.fingerprint}`);
      log(t('  私钥: {path}（0600，不要外传）', { path: join(dir, values.agent, 'private.pem') }));
      return;
    }
    if (sub === 'verify') {
      const targets = values.agent ? [values.agent] : identityList(dir).map((i) => i.agent);
      if (targets.length === 0) {
        log(t('没有可校验的身份（先 pod identity init --agent <name>）'));
        process.exitCode = 1;
        return;
      }
      let failed = 0;
      for (const agent of targets) {
        const r = identityVerify(agent, dir);
        log(`${r.ok ? '✅' : '❌'} ${agent}: ${r.reason}`);
        if (!r.ok) failed++;
      }
      if (failed > 0) process.exitCode = 1;
      return;
    }
    const rows = identityList(dir);
    if (values.json) {
      process.stdout.write(JSON.stringify(rows, null, 2) + '\n');
      return;
    }
    if (rows.length === 0) log(t('没有已建立的 agent 身份（pod identity init --agent <name>）'));
    for (const row of rows) log(`${row.ok ? '✅' : '⚠️'} ${row.agent}  fingerprint=${row.fingerprint ?? '-'}`);
    return;
  }

  if (cmd === 'delegate') {
    const rules = resolveRules(values.rules, POD_HOME);
    const identityDir = expandPath(rules.identity.dir);
    const delegationDir = expandPath(rules.delegation.dir);
    const auditDir = values['audit-dir'] ?? podPath('audit');
    const sub = positionals[1];
    if (sub === 'issue') {
      if (!values.parent || !values.child || !values.ttl) {
        console.error('pod delegate issue requires --parent <agent> --child <agent> --ttl <seconds> [--capability x]');
        process.exit(1);
      }
      const r = delegateIssue({
        parent: values.parent,
        child: values.child,
        capabilities: values.capability ?? [],
        ttlSeconds: Number.parseInt(values.ttl, 10),
        identityDir,
        delegationDir,
        auditDir,
        parentToken: values['parent-token'],
      });
      log(t('委托已签发：{parent} → {child}', { parent: values.parent, child: values.child }));
      log(t('  能力: {caps}', { caps: r.token.capabilities.join('、') || t('（无）') }));
      log(t('  到期: {ts}', { ts: r.token.expiresAt }));
      log(t('  文件: {path}', { path: r.file }));
      return;
    }
    if (sub === 'verify') {
      if (!values.in) {
        console.error('pod delegate verify requires --in <token.json>');
        process.exit(1);
      }
      const r = delegateVerify({ file: values.in, identityDir, rules });
      log(`${r.ok ? '✅' : '❌'} ${values.in}`);
      for (const hop of r.hops) log(t('  跳: {hop}', { hop }));
      log(t('  生效能力: {caps}', { caps: r.capabilities.join('、') || t('（无）') }));
      for (const err of r.errors) log(`  ✗ ${err}`);
      if (!r.ok) process.exitCode = 1;
      return;
    }
    if (sub === 'check') {
      if (!values['parent-policy'] || !values['child-policy']) {
        console.error('pod delegate check requires --parent-policy <file> --child-policy <file>');
        process.exit(1);
      }
      const parentPolicy = JSON.parse(readFileSync(values['parent-policy'], 'utf8')) as Policy;
      const childPolicy = JSON.parse(readFileSync(values['child-policy'], 'utf8')) as Policy;
      const r = delegateCheck({ parentPolicy, childPolicy, rules });
      log(`${r.ok ? '✅' : '❌'} ${t('委托收窄校验：{parent} → {child}', { parent: parentPolicy.agent, child: childPolicy.agent })}`);
      log(t('  父能力: {caps}', { caps: r.parent.join('、') || t('（无）') }));
      log(t('  子能力: {caps}', { caps: r.child.join('、') || t('（无）') }));
      if (r.escaped.length > 0) log(t('  ✗ 子 agent 扩大了权限: {caps}', { caps: r.escaped.join('、') }));
      if (r.forbidden.length > 0) log(t('  ✗ 命中了不可委托能力: {caps}', { caps: r.forbidden.join('、') }));
      if (!r.ok) process.exitCode = 1;
      return;
    }
    console.error('pod delegate <issue|verify|check>');
    process.exit(1);
  }

  if (cmd === 'grant') {
    const rules = resolveRules(values.rules, POD_HOME);
    const identityDir = expandPath(rules.identity.dir);
    const grantDir = expandPath(rules.grant.dir);
    const auditDir = values['audit-dir'] ?? podPath('audit');
    const sub = positionals[1];
    if (sub === 'issue') {
      const ttl = values.ttl ? Number.parseInt(values.ttl, 10) : 900;
      if (!values.agent || !values['issued-by']) {
        console.error('pod grant issue requires --agent <name> --issued-by <signer> [--ttl <seconds>]');
        process.exit(1);
      }
      const r = grantIssue({
        id: values.id ?? `grant-${Date.now()}-${randomUUID().slice(0, 4)}`,
        agent: values.agent,
        issuedBy: values['issued-by'],
        identityDir,
        grantDir,
        auditDir,
        ttlSeconds: ttl,
        singleUse: values['single-use'] === true,
        servers: values.server ? [values.server] : undefined,
        tools: values.tool ? [values.tool] : undefined,
        capabilities: values.capability,
        reason: values.reason,
      });
      log(t('令牌已签发：{id} → agent={agent}', { id: r.grant.claims.id, agent: r.grant.claims.agent }));
      log(t('  到期: {ts}{single}', { ts: r.grant.claims.expiresAt, single: r.grant.claims.singleUse ? t('（单次）') : '' }));
      log(t('  文件: {path}', { path: r.file }));
      return;
    }
    const rows = grantList(grantDir, identityDir);
    if (values.json) {
      process.stdout.write(JSON.stringify(rows, null, 2) + '\n');
      return;
    }
    if (rows.length === 0) log(t('没有已签发的令牌（pod grant issue ...）'));
    for (const row of rows) {
      log(
        `${row.valid ? '✅' : '❌'} ${row.id} agent=${row.agent} ` +
          t('{consumed}到期 {ts}', { consumed: row.consumed ? t('（已消费）') : '', ts: row.expiresAt }),
      );
    }
    return;
  }

  if (cmd === 'quarantine') {
    const rules = resolveRules(values.rules, POD_HOME);
    const file = expandPath(rules.quarantine.file);
    const auditDir = values['audit-dir'] ?? podPath('audit');
    const sub = positionals[1] ?? 'list';
    if (sub === 'add' || sub === 'remove') {
      if (!values.agent) {
        console.error(`pod quarantine ${sub} requires --agent <name>`);
        process.exit(1);
      }
      const by = values.approver ?? 'cli-user';
      const state =
        sub === 'add'
          ? quarantineAdd({ file, agent: values.agent, reason: values.reason ?? '人工熔断', by, auditDir })
          : quarantineRemove({ file, agent: values.agent, by, auditDir });
      log(
        sub === 'add'
          ? t('已熔断：{agent}', { agent: values.agent })
          : t('已解除熔断：{agent}', { agent: values.agent }),
      );
      log(t('  当前熔断 {n} 个 agent', { n: Object.keys(state.agents).length }));
      log(t('  网关下一次调用即生效（无需重启）。'));
      return;
    }
    const state = readQuarantineFile(file);
    const agents = Object.entries(state.agents);
    if (values.json) {
      process.stdout.write(JSON.stringify(state, null, 2) + '\n');
      return;
    }
    if (agents.length === 0) log(t('没有处于熔断状态的 agent'));
    for (const [agent, entry] of agents) {
      log(`⛔ ${agent} — ${entry.reason ?? ''}（${entry.at ?? ''} by ${entry.by ?? ''}）`);
    }
    return;
  }

  if (cmd === 'anomaly') {
    const rules = resolveRules(values.rules, POD_HOME);
    const auditDir = values['audit-dir'] ?? podPath('audit');
    const findings = detectAnomalies({
      auditDir,
      grantDir: expandPath(rules.grant.dir),
      delegationDir: expandPath(rules.delegation.dir),
      rules,
    });
    if (values.json) {
      process.stdout.write(JSON.stringify(findings, null, 2) + '\n');
      return;
    }
    if (findings.length === 0) {
      log(t('✅ 未发现信任传播异常（窗口 {min} 分钟）', { min: rules.anomaly.windowMinutes }));
      return;
    }
    for (const f of findings) log(`${f.severity === 'high' ? '🔴' : '🟠'} [${f.rule}] ${f.agent}: ${f.detail}`);
    if (values.audit) {
      for (const f of findings) {
        appendControlEvent({
          auditDir,
          agent: f.agent,
          kind: 'anomaly',
          reason: `anomaly:${f.rule}:${f.detail}`,
          payload: { severity: f.severity },
        });
      }
      log(t('（已写入审计链）'));
    }
    if (findings.some((f) => f.severity === 'high')) process.exitCode = 1;
    return;
  }

  if (cmd === 'trace') {
    const rules = resolveRules(values.rules, POD_HOME);
    const agent = positionals[1];
    if (!agent) {
      console.error('pod trace <agent> [--audit-dir <dir>]');
      process.exit(1);
    }
    const report = buildTrace({
      agent,
      auditDir: values['audit-dir'] ?? podPath('audit'),
      delegationDir: expandPath(rules.delegation.dir),
    });
    if (values.json) {
      process.stdout.write(JSON.stringify(report, null, 2) + '\n');
      return;
    }
    log(`# pod trace — ${agent}`);
    log('');
    log(t('## 委托链（上游）'));
    if (report.hops.length === 0) log(t('- 没有记录到委托关系（该 agent 不是任何委托的接收方）'));
    for (const hop of report.hops) {
      log(
        t('- {parent} → {child} [{caps}] @ {ts}', {
          parent: hop.parent,
          child: hop.child,
          caps: hop.capabilities.join('、') || t('无能力'),
          ts: hop.issuedAt,
        }),
      );
    }
    log('');
    log(t('## 下游（可能被影响的 agent）'));
    log(report.downstream.length === 0 ? t('- 无') : report.downstream.map((d) => `- ${d}`).join('\n'));
    log('');
    log(t('## 审计时间线'));
    log(
      t('- 相关事件 {total} 条，其中被拒绝/阻断 {blocked} 条', {
        total: report.entries.length,
        blocked: report.blocked.length,
      }),
    );
    for (const entry of report.blocked.slice(-10)) {
      log(
        t('  - {ts} {agent} {server}.{tool} → {decision}（{reason}）', {
          ts: entry.ts,
          agent: entry.agent,
          server: entry.server,
          tool: entry.tool,
          decision: entry.decision,
          reason: entry.reason ?? '',
        }),
      );
    }
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
    if (sub === 'sign') {
      if (!values.key || !values.in || !values.out) {
        console.error('pod policy sign requires --key <private.pem> --in <policy.json> --out <sig>');
        process.exit(1);
      }
      const policy = JSON.parse(readFileSync(values.in, 'utf8')) as Policy;
      writeFileSync(values.out, signPolicy(policy, readFileSync(values.key, 'utf8')) + '\n', 'utf8');
      log(`签名已写入: ${values.out}`);
      return;
    }
    if (sub === 'verify') {
      if (!values.key || !values.in || !values.sig) {
        console.error('pod policy verify requires --key <public.pem> --in <policy.json> --sig <sig>');
        process.exit(1);
      }
      const policy = JSON.parse(readFileSync(values.in, 'utf8')) as Policy;
      const ok = verifyPolicy(policy, readFileSync(values.sig, 'utf8').trim(), readFileSync(values.key, 'utf8'));
      if (!ok) {
        console.error(t('签名无效：策略内容与签名不匹配（可能被篡改）'));
        process.exit(1);
      }
      log(t('签名有效'));
      return;
    }
    console.error(`unknown policy subcommand: ${sub ?? '(none)'} (available: draft, sign, verify)`);
    console.error(usage());
    process.exit(1);
  }

  // ---------- 规则包（方向 B：订阅式加固） ----------

  if (cmd === 'rules') {
    const sub = positionals[1] ?? 'show';
    const rulesPath = values.rules ?? podPath('rules.json');
    const auditDir = values['audit-dir'] ?? podPath('audit');

    if (sub === 'show') {
      const rules = resolveRules(values.rules, POD_HOME);
      const counts = {
        frozenPaths: rules.freeze.paths.length,
        hookPatterns: rules.hookRisk.riskPatterns.length,
        injectionSignals: rules.injection.signals.length,
        injectionBlock: rules.injection.block,
        metadataPatterns: rules.toolMetadata.suspiciousPatterns.length,
        memoryPaths: rules.memory.paths.length,
        egress: rules.egress.enabled,
      };
      if (values.json) {
        process.stdout.write(
          JSON.stringify({ path: rulesPath, exists: existsSync(rulesPath), version: rules.version, counts }, null, 2) + '\n',
        );
        return;
      }
      log(`判定规则：${existsSync(rulesPath) ? rulesPath : '（尚未创建，当前使用代码内置默认值）'}`);
      log(`  version ${rules.version}`);
      log(
        `  冻结项 ${counts.frozenPaths} · 钩子模式 ${counts.hookPatterns} · 注入词 ${counts.injectionSignals}` +
          `（${counts.injectionBlock ? '命中即阻断' : '仅标记'}）` +
          ` · 元数据模式 ${counts.metadataPatterns} · 记忆路径 ${counts.memoryPaths}`,
      );
      log(`  egress 判定：${counts.egress ? '开启' : '关闭（默认）'}`);
      return;
    }

    if (sub === 'pack') {
      if (!values.key || !values.in || !values.out || !values.version || !values['issued-by']) {
        console.error(
          'pod rules pack requires --key <private.pem> --in <rules.json> --out <pack.json> --version <pack-version> --issued-by <who>',
        );
        process.exit(1);
      }
      const override = JSON.parse(readFileSync(values.in, 'utf8')) as RuleSetOverride;
      const pack = buildRulePack(override, {
        packVersion: values.version,
        issuedBy: values['issued-by'],
        note: values.note,
      });
      const signed = signRulePack(pack, readFileSync(values.key, 'utf8'));
      writeFileSync(values.out, JSON.stringify(signed, null, 2) + '\n', 'utf8');
      log(`规则包已签名并写入：${values.out}`);
      log(`  ${signed.issuedBy} · ${signed.packVersion} · ${signed.issuedAt}`);
      return;
    }

    if (sub === 'verify') {
      if (!values.in || !values.key) {
        console.error('pod rules verify requires --in <pack.json> --key <public.pem>');
        process.exit(1);
      }
      const pack = parseRulePack(readFileSync(values.in, 'utf8'));
      if (!verifyRulePack(pack, readFileSync(values.key, 'utf8'))) {
        console.error(t('签名无效：包内容与签名不匹配（可能被篡改），或公钥不对'));
        process.exit(1);
      }
      log(`✅ 签名有效（${pack.issuedBy} · ${pack.packVersion} · ${pack.issuedAt}）`);
      return;
    }

    if (sub === 'apply' || sub === 'pull') {
      let text: string;
      // 公钥解析顺序：--key（显式）> 云配置里的 rules_public_key / policy_public_key。
      // 注意它**只从本地读**：公钥不能和包走同一条通道，否则中间人换包时把公钥一起
      // 换掉，验签就成了摆设。所以这里没有"从响应里取公钥"的分支。
      let keyPem: string | undefined = values.key ? readFileSync(values.key, 'utf8') : undefined;
      if (sub === 'pull') {
        // 网络来源必须验签：这是信任边界，不留"跳过验签"的口子
        const fromCloud = values['from-cloud'] === true;
        if (!fromCloud && !values.url) {
          console.error(
            'pod rules pull requires --url <pack-url> [--key <public.pem>]\n' +
              '  或 --from-cloud：用 ~/.pod/cloud.json 的 api_url + sync_token 拉取该租户当前生效的包',
          );
          process.exit(1);
        }
        let url = values.url ?? '';
        let headers: Record<string, string> = {};
        let cloudNote = '';
        if (fromCloud) {
          const cfg = loadCloudConfig(values.config);
          const syncToken = cfg.sync_token ?? cfg.agents?.[0]?.sync_token;
          if (!syncToken) {
            console.error(`云配置里没有 sync_token，无法拉取规则包（${values.config ?? '~/.pod/cloud.json'}）`);
            process.exit(1);
          }
          url = `${cfg.api_url}/api/v1/rules/pack`;
          headers = { 'X-Sync-Token': syncToken };
          const keyPath = cfg.rules_public_key ?? cfg.policy_public_key;
          if (keyPath && !keyPem) keyPem = readFileSync(expandPath(keyPath), 'utf8');
          cloudNote = `（云配置 ${cfg.api_url}）`;
        }
        if (!keyPem) {
          console.error(
            '规则包验签需要公钥：加 --key <public.pem>，或在 ~/.pod/cloud.json 里配 rules_public_key。\n' +
              '网络来源不验签等于把加固通道交给中间人——这里不提供"跳过验签"的开关。',
          );
          process.exit(1);
        }
        const resp = await fetch(url, { headers });
        if (!resp.ok) {
          const detail = await resp.text().catch(() => '');
          console.error(`规则包拉取失败：HTTP ${resp.status} ${url}\n${detail.slice(0, 300)}`);
          process.exit(1);
        }
        if (fromCloud) {
          // 云端响应是信封 {pack_json, pack_version, ...}，真正的包在 pack_json 里
          const body = (await resp.json()) as { pack_json?: string; pack_version?: string };
          if (typeof body.pack_json !== 'string') {
            console.error('云端响应里没有 pack_json（服务端版本可能过旧）');
            process.exit(1);
          }
          text = body.pack_json;
          log(`云端当前生效版本：${body.pack_version ?? '?'} ${cloudNote}`);
        } else {
          text = await resp.text();
        }
      } else {
        if (!values.in) {
          console.error('pod rules apply requires --in <pack.json>');
          process.exit(1);
        }
        text = readFileSync(values.in, 'utf8');
      }
      const pack = parseRulePack(text);
      if (keyPem) {
        if (!verifyRulePack(pack, keyPem)) {
          console.error('规则包验签失败——拒绝应用（包内容与签名不匹配，或公钥不对）');
          process.exit(1);
        }
      } else {
        log('⚠️ 未提供 --key：跳过验签。本地文件适用，但无法证明这个包确实来自签发方。');
      }
      cmdRulesApply({
        pack,
        rulesOverride: values.rules,
        auditDir,
        allowRelax: values['allow-relax'] === true,
        allowExpansion: values['allow-expansion'] === true,
      });
      return;
    }

    console.error(`unknown rules subcommand: ${sub} (available: show, pack, verify, apply, pull)`);
    console.error(usage());
    process.exit(1);
  }

  if (cmd === 'graph') {
    const sub = positionals[1];
    const home = values.home ?? homedir();
    const outDir = values['out-dir'] ?? graphDir(home);
    // H4 埋点：graph 分发是唯一入口，在这里记一次即可覆盖全部子命令（retention 自身不计）
    if (sub) recordUsage(outDir, sub);
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
    if (sub === 'observe') {
      process.exit(
        cmdGraphObserve({
          auditDir: values['audit-dir'] ?? podPath('audit'),
          since: values.since,
          potentialPath: values.graph ?? join(outDir, 'potential.json'),
          out: values.out ?? join(outDir, 'observed.json'),
          json: values.json === true,
        }),
      );
    }
    if (sub === 'diff') {
      process.exit(
        cmdGraphDiff({
          potentialPath: values.graph ?? join(outDir, 'potential.json'),
          observedPath: values.observed ?? join(outDir, 'observed.json'),
          outDir,
          json: values.json === true,
        }),
      );
    }
    if (sub === 'mark') {
      const id = positionals[2];
      const verdict = positionals[3];
      if (!id || (verdict !== 'confirmed' && verdict !== 'false-positive')) {
        console.error('pod graph mark requires <id> confirmed|false-positive [--note <text>]');
        process.exit(1);
      }
      process.exit(
        cmdGraphMark({
          id,
          verdict,
          note: values.note,
          feedbackPath: join(outDir, 'feedback.json'),
          json: values.json === true,
        }),
      );
    }
    if (sub === 'baseline') {
      process.exit(
        cmdGraphBaseline({
          potentialPath: values.graph ?? join(outDir, 'potential.json'),
          observedPath: values.observed ?? join(outDir, 'observed.json'),
          agent: values.agent,
          outDir,
          capabilityDiffPath: values['capability-diff'] ?? join(outDir, 'capability-diff.json'),
          json: values.json === true,
        }),
      );
    }
    if (sub === 'retention') {
      process.exit(
        cmdGraphRetention({
          outDir,
          days: Number.parseInt(values.days ?? '14', 10),
          json: values.json === true,
        }),
      );
    }
    console.error(
      `unknown graph subcommand: ${sub ?? '(none)'} (available: build, observe, diff, baseline, toxic, explain, apply, mark, retention)`,
    );
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

  if (cmd === 'ui') {
    const portRaw = values.port;
    const port = portRaw ? Number.parseInt(portRaw, 10) : 8787;
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      console.error(`invalid --port: ${portRaw}`);
      process.exit(1);
    }
    await cmdUi({
      podHome: POD_HOME,
      port,
      token: values['auth-token'],
      log,
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

main().catch((err: unknown) => {
  log(`fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
  process.exit(1);
});
/**
 * 帮助文本按语言给两套完整文档，而不是逐行查词表。
 * 理由：用法说明是一篇**对齐排版**的文档（列宽、缩进都有意义），
 * 按句子拆开翻译会破坏排版；整体给一份反而更准、更好维护。
 * 其余输出仍走 `t()`（中文原文即 key）。
 */
function usage(locale: Locale = getLocale()): string {
  return locale === 'en-US' ? usageEn() : usageZh();
}

function usageEn(): string {
  return `pod — least-privilege compiler for AI agents

Usage:
  pod init [--template baseline|record]
  pod serve --agent <name> --server <name> --policy <file> \\
           --command <cmd> [--arg <value> ...] [--audit-dir <dir>] \\
           [--approval-timeout <sec>] [--pending-dir <dir>] [--alert-config <file>] \\
           [--transport stdio|http] [--port <n>] [--record-only] [--remember-approvals] \\
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
  pod pull-policy [--config <cloud.json>] [--api-url <url>] [--agent-id <n>] [--sync-token <t>] [--policy-public-key <pem>] [--require-signature] [--out-dir <dir>]
  pod policy draft [--audit-dir <dir>] [--agent <name>] [--server <name>] [--out <file>] [--diff <baseline.json>]
  pod policy sign --key <private.pem> --in <policy.json> --out <sig>
  pod policy verify --key <public.pem> --in <policy.json> --sig <sig>
  pod onboard [--config <path>] [--agent <name>] [--policy-dir <dir>] [--pod-bin <path>] [--yes] [--revert]
  pod digest [--since 7d] [--audit-dir <dir>] [--out <file>] [--json]
  pod coverage [--json] [--strict]
  pod scan [--json]
  pod harden [--out <dir>] [--agent <name>] [--rules <file>] [--audit-dir <dir>] \\
             [--no-evidence] [--audit] [--upload] [--config <cloud.json>] [--json]
  pod rules [show] [--rules <file>] [--json]
  pod rules pack --key <private.pem> --in <rules.json> --out <pack.json> \\
                 --version <pack-version> --issued-by <who> [--note <text>]
  pod rules verify --in <pack.json> --key <public.pem>
  pod rules apply --in <pack.json> [--key <public.pem>] [--rules <file>] [--allow-relax]
  pod rules pull --url <pack-url> --key <public.pem> [--rules <file>] [--allow-relax] [--allow-expansion]
  pod rules pull --from-cloud [--key <public.pem>] [--config <cloud.json>] [--rules <file>] [--allow-relax] [--allow-expansion]
  pod redteam --policy <file> [--rules <file>] [--scenarios <file>] [--llm] \\
              [--provider <id>] [--model <name>] [--export-surface <file>] [--out <dir>] [--json]
  pod posture [--rules <file>] [--baseline <file>] [--json] [--strict] [--audit]
  pod posture freeze [--rules <file>] [--baseline <file>]
  pod identity [list] | init --agent <name> | verify [--agent <name>] [--json]
  pod delegate issue --parent <agent> --child <agent> --ttl <seconds> [--capability <c> ...] [--parent-token <file>]
  pod delegate verify --in <token.json>
  pod delegate check --parent-policy <file> --child-policy <file>
  pod grant issue --agent <name> --issued-by <signer> [--ttl <seconds>] [--single-use] [--server <s>] [--tool <t>] [--capability <c> ...]
  pod grant list [--json]
  pod quarantine [list] | add --agent <name> [--reason <why>] | remove --agent <name>
  pod anomaly [--rules <file>] [--audit-dir <dir>] [--json] [--audit]
  pod trace <agent> [--audit-dir <dir>] [--json]
  pod ui [--port <n>]
  pod graph build [--home <dir>] [--config <path>] [--no-exec] [--timeout <ms>] [--out <file>] [--policy <file>] [--json]
  pod graph toxic [--graph <file>] [--out-dir <dir>] [--no-cross-agent] [--min-confidence <0-1>] [--max-paths <n>] [--diff <baseline.json>] [--json]
  pod graph explain <path-id|chain-id> [--out-dir <dir>] [--json]
  pod graph apply --policy <file> [--graph <file>] [--out <file>] [--json]
  pod graph observe [--audit-dir <dir>] [--since 7d] [--graph <potential.json>] [--out <file>] [--json]
  pod graph diff [--graph <potential.json>] [--observed <observed.json>] [--out-dir <dir>] [--json]
  pod graph mark <path-id|chain-id> confirmed|false-positive [--note <text>] [--json]
  pod graph baseline [--graph <potential.json>] [--observed <observed.json>] [--agent <name>] [--out-dir <dir>] [--capability-diff <file>] [--json]
  pod graph retention [--days 14] [--out-dir <dir>] [--json]
  pod --help [--lang zh-CN|en-US]

record: record-only mode (corpus collection) — wrap a real MCP server without blocking anything.
policy draft: compile a least-privilege policy draft from recorded calls (read-only; --diff against a baseline).
onboard: discover and take over local MCP servers (dry-run by default; --yes writes, --revert restores).
digest: local weekly security digest (audit + coverage + hash-chain health; no network).
coverage: managed coverage and config drift (--strict exits 1 when a server bypasses the gateway).
posture: control-plane posture (hooks, frozen config, memory, package sources, identities, delegation); rules from --rules or ~/.pod/rules.json.
harden: one-shot hardening audit deliverable — exposure scan + control-plane posture + least-privilege draft + evidence, all in one report directory. Local only; --upload sends just report.md + findings.json (never the raw evidence bundle).
rules: rule packs for subscribed hardening (pack/verify/apply/pull). A pack that loosens your existing rules is refused unless --allow-relax.
redteam: attack scenarios against your policy. The model (optional, --llm) only *proposes* scenarios as data; the verdict comes from the same pure pipeline the gateway uses, so results are reproducible and CI-able. Exit code 1 on a high-severity bypass.
identity/delegate/grant/quarantine/anomaly/trace: identities, delegation narrowing, JIT grants, quarantine, trust-propagation anomalies, pollution tracing.
approve/deny/pending: approval side channel (stdio is occupied by MCP; approve from another terminal).
watch: resident approval queue — new requests pop up immediately; approve/deny inline on a TTY.
snapshots/rollback: snapshots of high-risk writes (enable with serve --snapshot).
ingest: append external agent events (e.g. Codex PostToolUse hook) to the local hash chain.
audit: inspect the audit trail (with hash-chain verification).
`;
}

function usageZh(): string {
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
  pod pull-policy [--config <cloud.json>] [--api-url <url>] [--agent-id <n>] [--sync-token <t>] [--policy-public-key <pem>] [--require-signature] [--out-dir <dir>]
  pod policy draft [--audit-dir <dir>] [--agent <name>] [--server <name>] [--out <file>] [--diff <baseline.json>]
  pod policy sign --key <private.pem> --in <policy.json> --out <sig>
  pod policy verify --key <public.pem> --in <policy.json> --sig <sig>
  pod onboard [--config <path>] [--agent <name>] [--policy-dir <dir>] [--pod-bin <path>] [--yes] [--revert]
  pod digest [--since 7d] [--audit-dir <dir>] [--out <file>] [--json]
  pod coverage [--json] [--strict]
  pod scan [--json]
  pod harden [--out <dir>] [--agent <name>] [--rules <file>] [--audit-dir <dir>] \\
             [--no-evidence] [--audit] [--upload] [--config <cloud.json>] [--json]
  pod rules [show] [--rules <file>] [--json]
  pod rules pack --key <private.pem> --in <rules.json> --out <pack.json> \\
                 --version <pack-version> --issued-by <who> [--note <text>]
  pod rules verify --in <pack.json> --key <public.pem>
  pod rules apply --in <pack.json> [--key <public.pem>] [--rules <file>] [--allow-relax]
  pod rules pull --url <pack-url> --key <public.pem> [--rules <file>] [--allow-relax]
  pod rules pull --from-cloud [--key <public.pem>] [--config <cloud.json>] [--rules <file>] [--allow-relax] [--allow-expansion]
  pod redteam --policy <file> [--rules <file>] [--scenarios <file>] [--llm] \\
              [--provider <id>] [--model <name>] [--export-surface <file>] [--out <dir>] [--json]
  pod posture [--rules <file>] [--baseline <file>] [--json] [--strict] [--audit]
  pod posture freeze [--rules <file>] [--baseline <file>]
  pod identity [list] | init --agent <name> | verify [--agent <name>] [--json]
  pod delegate issue --parent <agent> --child <agent> --ttl <seconds> [--capability <c> ...] [--parent-token <file>]
  pod delegate verify --in <token.json>
  pod delegate check --parent-policy <file> --child-policy <file>
  pod grant issue --agent <name> --issued-by <signer> [--ttl <seconds>] [--single-use] [--server <s>] [--tool <t>] [--capability <c> ...]
  pod grant list [--json]
  pod quarantine [list] | add --agent <name> [--reason <why>] | remove --agent <name>
  pod anomaly [--rules <file>] [--audit-dir <dir>] [--json] [--audit]
  pod trace <agent> [--audit-dir <dir>] [--json]
  pod ui [--port <n>]
  pod graph build [--home <dir>] [--config <path>] [--no-exec] [--timeout <ms>] [--out <file>] [--policy <file>] [--json]
  pod graph toxic [--graph <file>] [--out-dir <dir>] [--no-cross-agent] [--min-confidence <0-1>] [--max-paths <n>] [--diff <baseline.json>] [--json]
  pod graph explain <path-id|chain-id> [--out-dir <dir>] [--json]
  pod graph apply --policy <file> [--graph <file>] [--out <file>] [--json]
  pod graph observe [--audit-dir <dir>] [--since 7d] [--graph <potential.json>] [--out <file>] [--json]
  pod graph diff [--graph <potential.json>] [--observed <observed.json>] [--out-dir <dir>] [--json]
  pod graph mark <path-id|chain-id> confirmed|false-positive [--note <text>] [--json]
  pod graph baseline [--graph <potential.json>] [--observed <observed.json>] [--agent <name>] [--out-dir <dir>] [--capability-diff <file>] [--json]
  pod graph retention [--days 14] [--out-dir <dir>] [--json]
  pod --help

record: 只录不拦模式（Phase 0 语料采集），从 dsh-mcp-manager 配置包装真实 MCP server。
policy draft: 从录制语料生成最小权限策略草稿（只读审计，不自动启用）；--diff 对比基线策略，输出收紧/放宽清单。
onboard: 发现并接管本机 MCP server（默认 dry-run；--yes 改写，--revert 回滚）。
digest: 本地安全周报（只读审计 + 覆盖率 + 哈希链健康，不联网）。
coverage: 受管覆盖率与配置漂移检查（--strict 有未受管 server 时退出码 1）。
posture: 控制平面姿态检查（钩子/冻结项/记忆/包来源/身份/委托），规则来自 --rules 或 ~/.pod/rules.json。
harden: 一次性加固审计交付物——暴露面 + 控制平面姿态 + 最小权限草稿 + 证据包，汇成一份报告目录。默认全程本地；--upload 只上传 report.md 与 findings.json，绝不上传原始证据包。
rules:  规则包（订阅式加固的分发单元）：pack/verify/apply/pull；放宽已有规则的包默认拒绝应用，--allow-relax 才放行。
redteam: 对你的策略做红队：模型（可选 --llm）只"提出"攻击场景这类数据，判定由网关同一条纯函数流水线给出，所以结论可复现、可进 CI；有高危绕过时退出码 1。
identity/delegate/grant/quarantine/anomaly/trace: 身份、委托收窄、JIT 令牌、熔断、信任传播异常、污染溯源。
approve/deny/pending: 审批旁路通道（stdio 被 MCP 占用，交互在另一个终端进行）。
watch:  长驻审批队列：新请求立即提示，TTY 下可直接批准/拒绝。
snapshots/rollback: 高危写操作的快照与回滚（serve --snapshot 开启）。
ingest: 把外部 agent 事件（如 Codex PostToolUse hook）追加进本地哈希链。
audit:  查看审计（含哈希链校验）。
`;
}
