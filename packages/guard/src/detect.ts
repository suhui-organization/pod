/**
 * 规则 × 事实 → findings（纯函数）。
 *
 * 每一条判定都对应 threats 目录里的一个 AG-xx，并在 finding 上保留 threat id，
 * 这样"漏洞清单"和"建议清单"能一一对上，用户不会看到一条无法处理的告警。
 */
import { existsSync } from 'node:fs';
import { expandHome, severityRank, type RuleSet, type Severity } from '@podsec/policy';
import { THREAT_BY_ID } from './catalog.js';
import { serverKey, type GuardBaseline } from './baseline.js';
import type { Facts, Finding, ServerFact } from './types.js';
import { CATEGORY_ORDER, SEVERITY_ORDER } from './types.js';

export interface DetectOptions {
  home: string;
  baseline?: GuardBaseline | null;
  now?: Date;
}

function includesHint(text: string, hints: string[]): boolean {
  const lower = text.toLowerCase();
  return hints.some((hint) => hint && lower.includes(hint.toLowerCase()));
}

/** server 的"身份串"：名字、包名、启动命令拼接，用来匹配能力提示词 */
function serverIdentity(server: ServerFact): string {
  return [server.name, server.package?.name ?? '', server.command, ...server.args].join(' ');
}

/** 命中 glob 的路径（** 与 * 都支持），与 posture 的 matchesGlob 同一语义 */
export function matchesGlob(path: string, pattern: string, home: string): boolean {
  const re = new RegExp(
    '^' +
      expandHome(pattern, home)
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*\*/g, '\u0000')
        .replace(/\*/g, '[^/]*')
        .replace(/\u0000/g, '.*') +
      '$',
  );
  return re.test(path);
}

function finding(input: {
  threat: string;
  harness: string;
  subject: string;
  message: string;
  evidence?: string[];
  severity?: Severity;
}): Finding {
  const entry = THREAT_BY_ID[input.threat];
  if (!entry) throw new Error(`未知威胁编号 ${input.threat}（catalog 与 detect 不同步）`);
  return {
    id: `${input.threat}:${input.harness}:${input.subject}`,
    threat: input.threat,
    category: entry.category,
    severity: input.severity ?? entry.severity,
    harness: input.harness,
    subject: input.subject,
    message: input.message,
    evidence: input.evidence ?? [],
  };
}

// ---------- AG-01 明文凭据 ----------

function detectSecrets(facts: Facts): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const secret of facts.secrets) {
    const dedupe = `${secret.file}|${secret.key}|${secret.category}|${secret.masked}`;
    if (seen.has(dedupe)) continue;
    seen.add(dedupe);
    out.push(
      finding({
        threat: 'AG-01',
        harness: harnessOfFile(facts, secret.file),
        subject: `${secret.file} → ${secret.key}`,
        message: `配置里发现明文 ${secret.category}（${secret.masked}）——任何能读这个文件的进程都拿到了它`,
        evidence: [`${secret.file}: ${secret.key} = ${secret.masked}`],
      }),
    );
  }
  return out;
}

function harnessOfFile(facts: Facts, file: string): string {
  const server = facts.servers.find((s) => s.file === file);
  if (server) return server.harness;
  const hook = facts.hooks.find((h) => h.file === file);
  if (hook) return hook.harness;
  const mem = facts.memory.find((m) => m.file === file);
  if (mem) return mem.harness;
  return 'unknown';
}

// ---------- AG-02 / AG-03 / AG-08 ----------

function isLocalHost(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, '').toLowerCase();
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0' || h.endsWith('.localhost');
}

function detectServers(rules: RuleSet, facts: Facts): Finding[] {
  const out: Finding[] = [];
  for (const server of facts.servers) {
    if (rules.packages.requireVersionPin && server.package && (server.package.version === null || server.package.version === 'latest')) {
      out.push(
        finding({
          threat: 'AG-02',
          harness: server.harness,
          subject: `${server.name}@${server.file}`,
          message: `MCP server "${server.name}" 从 npx 拉取 ${server.package.name}${server.package.version ? '@' + server.package.version : '（未写版本）'}，上游每次发布都会进入本机`,
          evidence: [`${server.file}: ${[server.command, ...server.args].join(' ')}`],
        }),
      );
    }

    if (!server.behindGateway) {
      out.push(
        finding({
          threat: 'AG-03',
          harness: server.harness,
          subject: `${server.name}@${server.file}`,
          message: `MCP server "${server.name}" 未经过 pod 网关——策略、审批、审计对它都不生效`,
          evidence: [`${server.file}: ${[server.command, ...server.args].join(' ') || server.url || ''}`],
        }),
      );
    }

    // AG-08：远程端点 / 关闭鉴权开关 / 绑定全网卡
    const omitAuth = [...server.args, ...server.envKeys].some((v) => /DANGEROUSLY_OMIT_AUTH/i.test(v));
    const bindAll = server.args.some((v) => /(^|\s|=|\/\/)0\.0\.0\.0(\b|:)/.test(v));
    if (omitAuth || bindAll) {
      out.push(
        finding({
          threat: 'AG-08',
          harness: server.harness,
          subject: `${server.name}@${server.file}`,
          message: omitAuth
            ? `MCP server "${server.name}" 关闭了鉴权（DANGEROUSLY_OMIT_AUTH）——工具执行变成了无鉴权的网络接口`
            : `MCP server "${server.name}" 绑定 0.0.0.0——本机之外的进程也能连上它的工具执行面`,
          evidence: [`${server.file}: ${[server.command, ...server.args].join(' ')}`],
        }),
      );
    }
    if (server.url) {
      let host = '';
      let scheme = '';
      try {
        const parsed = new URL(server.url);
        host = parsed.hostname;
        scheme = parsed.protocol.replace(':', '');
      } catch {
        // 解析不了的 URL 本身就是个问题，按远程端点报出来
        host = '';
      }
      const allowed = rules.guard.allowedRemoteHosts ?? [];
      const allowlisted = host !== '' && allowed.some((pattern) => matchesGlob(host, pattern, ''));
      if (!allowlisted && !isLocalHost(host)) {
        out.push(
          finding({
            threat: 'AG-08',
            harness: server.harness,
            subject: `${server.name}@${server.file}`,
            severity: scheme === 'http' ? 'high' : 'medium',
            message:
              host === ''
                ? `MCP server "${server.name}" 的端点 URL 无法解析，无法确认它连到哪里`
                : scheme === 'http'
                  ? `MCP server "${server.name}" 通过明文 HTTP 连到远程主机 ${host}——token 与工具参数在链路上可读可改`
                  : `MCP server "${server.name}" 连到远程主机 ${host}——确认它强制鉴权，且只授予必需的工具`,
            evidence: [`${server.file}: ${server.name} → ${server.url}`],
          }),
        );
      }
    }
  }
  return out;
}

// ---------- AG-04 项目级自动执行 ----------

function detectProjects(facts: Facts): Finding[] {
  const out: Finding[] = [];
  for (const project of facts.projects) {
    if (project.autoExecConfigs.length === 0) continue;
    out.push(
      finding({
        threat: 'AG-04',
        harness: 'workspace',
        subject: project.root,
        message: `工作区 ${project.root} 里有 ${project.autoExecConfigs.length} 个 MCP 配置：接受一次"信任此文件夹"就会以你的权限启动其中的 server`,
        evidence: project.autoExecConfigs.map((path) => `${project.root}/${path}`),
      }),
    );
  }
  return out;
}

// ---------- AG-05 / AG-06 / AG-13 钩子与放宽开关 ----------

function detectHooks(rules: RuleSet, facts: Facts): Finding[] {
  const out: Finding[] = [];
  const patterns = rules.hookRisk.riskPatterns.map((p) => ({ ...p, regex: new RegExp(p.re) }));
  for (const hook of facts.hooks) {
    const trusted = rules.hookRisk.trustedSources.some((pattern) => matchesGlob(hook.file, pattern, ''));
    for (const pattern of patterns) {
      if (!pattern.regex.test(hook.command)) continue;
      out.push(
        finding({
          threat: 'AG-05',
          harness: hook.harness,
          subject: `${hook.file}#${hook.index}`,
          severity: trusted ? 'low' : pattern.severity,
          message: `钩子（${hook.event}）命中风险规则 ${pattern.id}：${pattern.why ?? '钩子内容可疑'}${trusted ? '（来源在 trustedSources 里，已降级）' : ''}`,
          evidence: [`${hook.file}: ${hook.command}`],
        }),
      );
    }
    for (const flag of rules.guard.dangerousFlags) {
      if (!hook.command.includes(flag)) continue;
      out.push(
        finding({
          threat: 'AG-06',
          harness: hook.harness,
          subject: `${hook.file}#${hook.index}:${flag}`,
          message: `钩子用 "${flag}" 启动 agent——审批闸门被这个参数整条绕过`,
          evidence: [`${hook.file}: ${hook.command}`],
        }),
      );
      break; // 一条命令命中多个同义 flag 只报一次，不制造重复告警
    }
  }
  for (const server of facts.servers) {
    const argv = [server.command, ...server.args].join(' ');
    for (const flag of rules.guard.dangerousFlags) {
      if (!argv.includes(flag)) continue;
      out.push(
        finding({
          threat: 'AG-06',
          harness: server.harness,
          subject: `${server.name}@${server.file}:${flag}`,
          message: `MCP server "${server.name}" 用 "${flag}" 启动子进程——审批闸门被这个参数整条绕过`,
          evidence: [`${server.file}: ${argv}`],
        }),
      );
      break;
    }
  }
  return out;
}

function detectPlugins(rules: RuleSet, home: string): Finding[] {
  const hits: string[] = [];
  for (const pattern of rules.guard.pluginPaths) {
    const expanded = expandHome(pattern, home);
    if (existsSync(expanded.replace(/\/\*\*$/, ''))) hits.push(pattern);
    else if (!pattern.includes('*') && existsSync(expanded)) hits.push(pattern);
  }
  if (hits.length === 0) return [];
  return [
    finding({
      threat: 'AG-13',
      harness: 'plugins',
      subject: hits.join(','),
      message: `发现 ${hits.length} 个第三方插件/技能目录：它们把提示词、脚本和钩子一起带进来，安装即接受全部三样`,
      evidence: hits,
    }),
  ];
}

// ---------- AG-07 记忆 ----------

function detectMemory(facts: Facts): Finding[] {
  const out: Finding[] = [];
  for (const mem of facts.memory) {
    if (!mem.exists || mem.managed) continue;
    out.push(
      finding({
        threat: 'AG-07',
        harness: mem.harness,
        subject: mem.file,
        message: `${mem.file} 是长期记忆，但没有纳入 rules.memory.paths——被改写时不会有人知道，而它会影响之后每一次会话`,
        evidence: [`${mem.file}（${mem.bytes} 字节）`],
      }),
    );
  }
  return out;
}

// ---------- AG-09 致命三角 ----------

function detectTrifecta(rules: RuleSet, facts: Facts): Finding[] {
  const out: Finding[] = [];
  const byHarness = new Map<string, ServerFact[]>();
  for (const server of facts.servers) {
    const list = byHarness.get(server.harness);
    if (list) list.push(server);
    else byHarness.set(server.harness, [server]);
  }
  for (const [harness, list] of byHarness) {
    const privateData = list.filter((s) => includesHint(serverIdentity(s), rules.guard.privateDataHints));
    const egress = list.filter((s) => includesHint(serverIdentity(s), rules.guard.egressHints));
    if (privateData.length === 0 || egress.length === 0) continue;
    out.push(
      finding({
        threat: 'AG-09',
        harness,
        subject: harness,
        message: `${harness} 同时具备"读私密数据"与"向外发送"能力（致命三角的两条边：${privateData.map((s) => s.name).join('、')} → ${egress.map((s) => s.name).join('、')}）——它读到的任何不可信内容都可能被发出去`,
        evidence: [
          `读私密：${privateData.map((s) => `${s.name}@${s.file}`).join('、')}`,
          `可外发：${egress.map((s) => `${s.name}@${s.file}`).join('、')}`,
        ],
      }),
    );
  }
  return out;
}

// ---------- AG-10 共享凭据 ----------

function detectSharedCredentials(facts: Facts): Finding[] {
  const groups = new Map<string, Set<string>>();
  for (const secret of facts.secrets) {
    const key = `${secret.category}|${secret.masked}`;
    const files = groups.get(key) ?? new Set<string>();
    files.add(secret.file);
    groups.set(key, files);
  }
  const out: Finding[] = [];
  for (const [key, files] of groups) {
    if (files.size < 2) continue;
    const [category, masked] = key.split('|');
    out.push(
      finding({
        threat: 'AG-10',
        harness: 'multiple',
        subject: key,
        message: `同一份 ${category}（${masked}）出现在 ${files.size} 个配置里——出事时无法判断是谁做的，也无法单独吊销`,
        evidence: [...files].sort(),
      }),
    );
  }
  return out;
}

// ---------- AG-11 / AG-16 覆盖与可见性 ----------

function detectCoverage(rules: RuleSet, facts: Facts): Finding[] {
  const out: Finding[] = [];
  for (const harness of facts.harnesses) {
    if (!harness.installed) continue;
    if (rules.guard.requireManaged && !harness.managed) {
      out.push(
        finding({
          threat: 'AG-11',
          harness: harness.id,
          subject: harness.id,
          message: `${harness.label} 在本机上是装着的，但没有策略、身份或审计记录（发现的证据：${harness.evidence.join('、')}）`,
          evidence: harness.evidence,
        }),
      );
    }
    if (rules.auditHealth.enabled && harness.managed && !harness.managedBy.includes('audit')) {
      out.push(
        finding({
          threat: 'AG-16',
          harness: harness.id,
          subject: harness.id,
          message: `${harness.label} 有治理记录但没有审计链——它做过什么无法证明（managedBy: ${harness.managedBy.join('/')}）`,
          evidence: harness.agentNames.length > 0 ? harness.agentNames : harness.evidence,
        }),
      );
    }
  }
  return out;
}

// ---------- AG-12 配置未冻结 ----------

function detectFreeze(facts: Facts): Finding[] {
  if (facts.baselinePresent) return [];
  if (facts.servers.length === 0 && facts.hooks.length === 0 && facts.harnesses.every((h) => !h.installed)) {
    return [];
  }
  return [
    finding({
      threat: 'AG-12',
      harness: 'machine',
      subject: 'posture-baseline',
      message:
        '尚未建立姿态基线：agent 配置、记忆文件、钩子被改写时不会报出来（攻击者只需要改一个参数就能把闸门悄悄摘掉）',
      evidence: ['pod posture freeze'],
    }),
  ];
}

// ---------- AG-14 rug pull ----------

function detectRugPull(rules: RuleSet, facts: Facts, baseline: GuardBaseline | null | undefined): Finding[] {
  if (!baseline || !rules.packages.requireIntegrity) return [];
  const out: Finding[] = [];
  const current = new Map<string, { fingerprint: string; server: ServerFact }>();
  for (const server of facts.servers) {
    current.set(serverKey(server.harness, server.name), { fingerprint: server.fingerprint, server });
  }
  for (const [key, entry] of current) {
    const before = baseline.servers[key];
    if (before === undefined) {
      out.push(
        finding({
          threat: 'AG-14',
          harness: entry.server.harness,
          subject: key,
          severity: 'medium',
          message: `基线之后新增了 MCP server "${entry.server.name}"（${entry.server.file}）——确认这是你自己加的`,
          evidence: [`${entry.server.file}: ${[entry.server.command, ...entry.server.args].join(' ')}`],
        }),
      );
      continue;
    }
    if (before !== entry.fingerprint) {
      out.push(
        finding({
          threat: 'AG-14',
          harness: entry.server.harness,
          subject: key,
          message: `MCP server "${entry.server.name}" 的启动命令与基线不一致——同名 server 可能被换成了另一个包（rug pull）`,
          evidence: [`${entry.server.file}: ${[entry.server.command, ...entry.server.args].join(' ')}`],
        }),
      );
    }
  }
  return out;
}

// ---------- AG-15 / AG-17 闸门关着 ----------

function detectDisabledControls(rules: RuleSet, facts: Facts): Finding[] {
  const out: Finding[] = [];
  const egressServers = facts.servers.filter((s) => includesHint(serverIdentity(s), rules.guard.egressHints));
  if (!rules.injection.block) {
    out.push(
      finding({
        threat: 'AG-15',
        harness: 'machine',
        subject: 'injection.block',
        message: 'rules.injection.block 是关的：工具响应里的注入内容会原样回到 agent 上下文（这正是 EchoLeak 类的入口）',
        evidence: ['rules.injection.block = false'],
      }),
    );
  }
  if (!rules.egress.enabled && egressServers.length > 0) {
    out.push(
      finding({
        threat: 'AG-15',
        harness: 'machine',
        subject: 'egress.enabled',
        message: `rules.egress 未启用，但本机有 ${egressServers.length} 个能向外发送的 server（${egressServers.map((s) => s.name).join('、')}）——数据出机器前没有可判定的闸门`,
        evidence: egressServers.map((s) => `${s.name}@${s.file}`),
      }),
    );
  }
  if (!rules.toolMetadata.block && facts.servers.length > 0) {
    out.push(
      finding({
        threat: 'AG-17',
        harness: 'machine',
        subject: 'toolMetadata.block',
        message: 'rules.toolMetadata.block 是关的：工具描述里的隐藏指令不会被从 tools/list 摘掉，模型会直接读到',
        evidence: ['rules.toolMetadata.block = false'],
      }),
    );
  }
  return out;
}

// ---------- 入口 ----------

export function detect(rules: RuleSet, facts: Facts, opts: DetectOptions): Finding[] {
  const findings = [
    ...detectSecrets(facts),
    ...detectServers(rules, facts),
    ...detectProjects(facts),
    ...detectHooks(rules, facts),
    ...detectPlugins(rules, opts.home),
    ...detectMemory(facts),
    ...detectTrifecta(rules, facts),
    ...detectSharedCredentials(facts),
    ...detectCoverage(rules, facts),
    ...detectFreeze(facts),
    ...detectRugPull(rules, facts, opts.baseline),
    ...detectDisabledControls(rules, facts),
  ];
  return dedupe(findings).sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      CATEGORY_ORDER.indexOf(a.category) - CATEGORY_ORDER.indexOf(b.category) ||
      a.id.localeCompare(b.id),
  );
}

/** 同一 id 只留一条（不同检测器可能从不同角度命中同一处） */
function dedupe(findings: Finding[]): Finding[] {
  const seen = new Map<string, Finding>();
  for (const item of findings) {
    const existing = seen.get(item.id);
    if (!existing) {
      seen.set(item.id, item);
      continue;
    }
    // 合并证据，保留更严重的级别
    const merged: Finding = {
      ...existing,
      severity: severityRank(item.severity) > severityRank(existing.severity) ? item.severity : existing.severity,
      evidence: [...new Set([...existing.evidence, ...item.evidence])],
    };
    seen.set(item.id, merged);
  }
  return [...seen.values()];
}
