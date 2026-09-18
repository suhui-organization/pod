/**
 * 纳管（enroll）：把扫描到的 harness 记进 pod 的管理范围。
 *
 * 这是控制台里唯一会改变本机状态的路径（只读是默认，写操作要显式）。
 * 三条硬约束：
 * 1. 只写 ~/.pod 下的产物，不碰任何 harness 的配置——改写配置是
 *    `pod onboard --yes` 的事，那条路有备份与 --revert；
 * 2. 写出来的策略是零权限起点（defaultDecision=deny、无 server 规则），
 *    与 threat-model §3「新 agent 默认零权限」一致；
 * 3. 每次纳管/移除都写进控制平面哈希链，可回答"是谁纳进来的"。
 *
 * 为什么纳管要建身份：agent 名只是字符串，谁都能自称。ed25519 身份才让
 * "这次调用是谁做的"可回答（T12）。
 */
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { appendControlEvent } from '@podsec/audit';
import { generateAgentIdentity, loadAgentIdentity } from '@podsec/identity';
import { t } from '@podsec/i18n';
import { DEFAULT_SECRET_RULES, type Policy } from '@podsec/policy';

/** agent 名会拼进路径与哈希链，规则与 @podsec/identity 的 sanitizeAgent 一致 */
const AGENT_NAME_RE = /^[A-Za-z0-9._-]{1,64}$/;

export function assertAgentName(agent: string): void {
  if (!AGENT_NAME_RE.test(agent) || agent === '.' || agent === '..') {
    throw new Error(
      t('非法 agent 名：{agent}（只允许 A-Za-z0-9._-，长度 1-64；名字会进路径与审计链）', {
        agent,
      }),
    );
  }
}

export interface EnrollmentRecord {
  agent: string;
  /** 来自哪个 harness（claude-code / codex / …） */
  harness: string;
  /** 纳管时创建的策略文件名（相对策略目录）；已存在策略时为 null */
  policyFile: string | null;
  /** true = 这份策略是纳管时写下的（移除时可以安全删掉） */
  policyCreatedByEnroll: boolean;
  identityFingerprint: string | null;
  enrolledAt: string;
  enrolledBy: string;
}

export interface EnrollmentState {
  v: 1;
  agents: Record<string, EnrollmentRecord>;
}

export function enrollmentStatePath(podHome: string): string {
  return join(podHome, 'console', 'enrolled.json');
}

/** 该 agent 的审计目录（与 pod 其它命令的布局一致：<auditDir>/<agent>/） */
function agentAuditDir(auditDir: string, agent: string): string {
  return join(auditDir, agent);
}

/**
 * 读纳管台账。损坏时不抛错：它是"哪些是控制台纳管的"的记账，不是安全判定的
 * 输入（判定看的是身份/策略/审计本身）。保守处理即可。
 */
export function readEnrollment(statePath: string): EnrollmentState {
  if (!existsSync(statePath)) return { v: 1, agents: {} };
  try {
    const raw = JSON.parse(readFileSync(statePath, 'utf8')) as Partial<EnrollmentState>;
    if (raw.v !== 1 || typeof raw.agents !== 'object' || raw.agents === null) {
      return { v: 1, agents: {} };
    }
    return { v: 1, agents: raw.agents };
  } catch {
    return { v: 1, agents: {} };
  }
}

function writeEnrollment(statePath: string, state: EnrollmentState): void {
  mkdirSync(dirname(statePath), { recursive: true });
  writeFileSync(statePath, JSON.stringify(state, null, 2) + '\n', 'utf8');
}

/** 纳管时写下的策略：零权限起点（未登记 server 一律拒绝） */
export function enrollmentPolicyTemplate(agent: string): Policy {
  return {
    version: '0.1.0',
    agent,
    defaultDecision: 'deny',
    servers: {},
    secrets: DEFAULT_SECRET_RULES,
  };
}

/** 已有策略是否已绑定这个 agent（有就不重复建，避免一个 agent 两份策略） */
function findExistingPolicy(
  policyDir: string,
  agent: string,
): { file: string; path: string } | null {
  if (!existsSync(policyDir)) return null;
  let files: string[];
  try {
    files = readdirSync(policyDir)
      .filter((f) => f.endsWith('.json'))
      .sort();
  } catch {
    return null;
  }
  for (const file of files) {
    try {
      const parsed = JSON.parse(readFileSync(join(policyDir, file), 'utf8')) as {
        agent?: unknown;
      };
      if (parsed.agent === agent) return { file, path: join(policyDir, file) };
    } catch {
      // 解析失败的文件由 pod lint 与控制台的 notes 负责报，这里跳过
    }
  }
  return null;
}

export interface EnrollOptions {
  podHome: string;
  /** harness id（claude-code / codex / …），用于记账与提示 */
  harness: string;
  agent: string;
  policyDir?: string;
  auditDir?: string;
  identityDir?: string;
  /** 谁发起的：'pod ui' 或 'pod agents'；写进审计 */
  enrolledBy?: string;
  /** 扫描得到的 server 概况，用来给"纳管 ≠ 拦住"的提示 */
  serverSummary?: { total: number; behindGateway: number };
  now?: Date;
}

export interface EnrollResult {
  agent: string;
  harness: string;
  /** true = 身份与策略此前都已存在，本次没有改动 */
  alreadyManaged: boolean;
  changed: { identity: boolean; policy: boolean; auditDir: boolean };
  identityFingerprint: string | null;
  policyFile: string | null;
  /** 诚实的边界说明：纳管做了什么、没做什么 */
  notes: string[];
  nextSteps: string[];
}

/**
 * 纳管一个 agent：建身份 + 写零权限策略 + 建审计目录 + 入链。
 * 幂等：已存在的部分不动，重复调用只返回 alreadyManaged=true。
 */
export function enrollAgent(opts: EnrollOptions): EnrollResult {
  const agent = opts.agent.trim();
  assertAgentName(agent);
  const podHome = opts.podHome;
  const policyDir = opts.policyDir ?? join(podHome, 'policies');
  const auditDir = opts.auditDir ?? join(podHome, 'audit');
  const identityDir = opts.identityDir ?? join(podHome, 'identity');
  const now = opts.now ?? new Date();
  const actor = opts.enrolledBy ?? 'pod ui';
  const statePath = enrollmentStatePath(podHome);

  const changed = { identity: false, policy: false, auditDir: false };
  const notes: string[] = [];

  // 审计目录先就位：控制平面事件现在写在 <auditDir>/<agent>/control.jsonl 里，
  // 而 appendControlEvent 会顺手 mkdir。先建就先建，但**必须在这里判定**，
  // 否则 changed.auditDir 会永远报 false——明明是我们建的，却说自己没建。
  const auditPath = agentAuditDir(auditDir, agent);
  if (!existsSync(auditPath)) {
    mkdirSync(auditPath, { recursive: true });
    changed.auditDir = true;
  }

  // 1) 身份
  const existingIdentity = loadAgentIdentity(agent, identityDir);
  let identityFingerprint = existingIdentity?.fingerprint ?? null;
  if (!existingIdentity) {
    const identity = generateAgentIdentity(agent, identityDir, now);
    identityFingerprint = identity.fingerprint;
    changed.identity = true;
    appendControlEvent({
      auditDir,
      // 事件落在**被纳管的那个 agent** 的链上（audit/<agent>/control.jsonl），
      // 而不是机器级的 _control：pod sync 是按绑定 agent 过滤事件的
      // （e.agent === local_agent），写进 _control 会让云端"控制平面"页永远空着。
      agent,
      kind: 'identity',
      tool: 'enroll',
      reason: `console:enroll:${agent}:identity:${identity.fingerprint}`,
      payload: { agent, harness: opts.harness, by: actor, fingerprint: identity.fingerprint },
    });
  }

  // 2) 策略：已有绑定就不动
  const existingPolicy = findExistingPolicy(policyDir, agent);
  let policyFile: string | null = existingPolicy?.file ?? null;
  let policyCreated = false;
  if (!existingPolicy) {
    const file = `${agent}.json`;
    mkdirSync(policyDir, { recursive: true });
    writeFileSync(
      join(policyDir, file),
      JSON.stringify(enrollmentPolicyTemplate(agent), null, 2) + '\n',
      'utf8',
    );
    policyFile = file;
    policyCreated = true;
    changed.policy = true;
    appendControlEvent({
      auditDir,
      agent,
      kind: 'config-change',
      tool: 'enroll',
      reason: `console:enroll:${agent}:policy:${file}`,
      payload: { agent, harness: opts.harness, by: actor, policy: file, defaultDecision: 'deny' },
    });
  }

  // 3) 台账
  const state = readEnrollment(statePath);
  const previous = state.agents[agent];
  const alreadyManaged = !changed.identity && !changed.policy && Boolean(previous);
  state.agents[agent] = {
    agent,
    harness: opts.harness,
    policyFile,
    policyCreatedByEnroll: policyCreated || previous?.policyCreatedByEnroll === true,
    identityFingerprint,
    enrolledAt: previous?.enrolledAt ?? now.toISOString(),
    enrolledBy: actor,
  };
  writeEnrollment(statePath, state);

  notes.push(t('纳管只写 ~/.pod 下的产物，不改动 harness 的配置。'));
  if (opts.serverSummary && opts.serverSummary.behindGateway < opts.serverSummary.total) {
    notes.push(
      t(
        '该 harness 有 {total} 个 MCP server，其中 {behind} 个经过 pod 网关——纳管本身不会拦住其余 {rest} 个。',
        {
          total: opts.serverSummary.total,
          behind: opts.serverSummary.behindGateway,
          rest: opts.serverSummary.total - opts.serverSummary.behindGateway,
        },
      ),
    );
  }
  if (changed.policy) {
    notes.push(t('新建的策略是零权限起点（未登记 server 一律拒绝），需要采集语料后编译最小权限策略。'));
  }

  const nextSteps = [
    t('pod onboard --yes    # 把该 harness 的 MCP server 包进网关；不改配置就只有记录、没有闸门'),
    t('pod record --agent {agent} --server <name>    # 先只录不拦，采集真实调用', { agent }),
    t('pod policy draft --agent {agent} --diff <baseline>    # 编译最小权限策略，复核后再切执法', {
      agent,
    }),
    t('pod guard scan --strict    # 随时看这个 agent 的漏洞清单'),
  ];

  return {
    agent,
    harness: opts.harness,
    alreadyManaged,
    changed,
    identityFingerprint,
    policyFile,
    notes,
    nextSteps,
  };
}

export interface ForgetOptions {
  podHome: string;
  agent: string;
  policyDir?: string;
  auditDir?: string;
  identityDir?: string;
  /** true = 连私钥一起删（默认保留：删了就无法再证明历史上的调用是它做的） */
  purgeIdentity?: boolean;
  actor?: string;
}

export interface ForgetResult {
  agent: string;
  found: boolean;
  removed: { policy: boolean; identity: boolean };
  notes: string[];
}

/**
 * 移除纳管：删掉纳管时创建的那份策略，并按需删身份。
 *
 * 只删自己写下的东西：策略文件只有在台账记着"纳管创建"、且文件里的 agent 与
 * 请求一致时才删。用户自己写的策略不在移除范围内。
 */
export function forgetAgent(opts: ForgetOptions): ForgetResult {
  const agent = opts.agent.trim();
  assertAgentName(agent);
  const podHome = opts.podHome;
  const policyDir = opts.policyDir ?? join(podHome, 'policies');
  const auditDir = opts.auditDir ?? join(podHome, 'audit');
  const identityDir = opts.identityDir ?? join(podHome, 'identity');
  const actor = opts.actor ?? 'pod ui';
  const statePath = enrollmentStatePath(podHome);
  const state = readEnrollment(statePath);
  const record = state.agents[agent];
  const notes: string[] = [];
  const removed = { policy: false, identity: false };

  if (!record) {
    notes.push(t('台账里没有这个 agent 的纳管记录——可能是手动创建的，pod 不动它。'));
    return { agent, found: false, removed, notes };
  }

  if (record.policyCreatedByEnroll && record.policyFile) {
    const path = join(policyDir, record.policyFile);
    try {
      const parsed = JSON.parse(readFileSync(path, 'utf8')) as { agent?: unknown };
      if (parsed.agent === agent) {
        unlinkSync(path);
        removed.policy = true;
      } else {
        notes.push(t('策略文件 {file} 现在绑定的是别的 agent，未删除', { file: record.policyFile }));
      }
    } catch {
      notes.push(t('策略文件 {file} 不存在或无法解析，跳过删除', { file: record.policyFile }));
    }
  } else if (record.policyFile) {
    notes.push(t('保留 {file}：它不是纳管时创建的，不删用户自己的策略', { file: record.policyFile }));
  }

  if (opts.purgeIdentity) {
    const dir = join(identityDir, agent);
    if (existsSync(dir)) {
      rmSync(dir, { recursive: true, force: true });
      removed.identity = true;
    }
  } else {
    notes.push(t('身份与私钥保留（删掉就无法再证明历史上的调用是它做的）；要删用 --purge-identity。'));
  }

  // 审计目录只在空的时候删：里面有链数据就是证据，任何情况下都不动
  try {
    const dir = agentAuditDir(auditDir, agent);
    if (existsSync(dir) && readdirSync(dir).length === 0) rmSync(dir, { recursive: true, force: true });
  } catch {
    // 删不掉不影响"移除纳管"的语义，忽略
  }

  delete state.agents[agent];
  writeEnrollment(statePath, state);

  appendControlEvent({
    auditDir,
    // 同上：写进被移除纳管的那个 agent 的链，才会上云
    agent,
    kind: 'config-change',
    tool: 'forget',
    reason: `console:forget:${agent}`,
    payload: { agent, by: actor, removedPolicy: removed.policy, removedIdentity: removed.identity },
  });

  return { agent, found: true, removed, notes };
}
