// pod redteam 的端到端测试：真跑 CLI 子进程。
//
// 模型路径一律走 mock provider（离线、不发请求），并且用 POD_LLM_CONFIG 把
// 配置指到临时文件——否则测试会读到开发者真实的 ~/.pod/llm.json。
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { beforeEach, describe, expect, it } from 'vitest';
import { DEFAULT_SECRET_RULES, type Policy } from '@podsec/policy';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_INDEX = join(HERE, '../src/index.ts');

let root: string;
let auditDir: string;
let policyPath: string;
let llmConfigPath: string;
let outDir: string;

function run(
  args: string[],
  expectedStatus = 0,
  env: Record<string, string> = {},
): { out: string; stdout: string; stderr: string; status: number | null } {
  const res = spawnSync(process.execPath, ['--import', 'tsx', CLI_INDEX, ...args], {
    encoding: 'utf8',
    env: {
      ...process.env,
      POD_LLM_CONFIG: llmConfigPath,
      // 清掉可能来自开发者环境的模型配置，保证测试可复现
      POD_LLM_PROVIDER: '',
      POD_LLM_MODEL: '',
      POD_LLM_API_KEY: '',
      POD_LLM_BASE_URL: '',
      ...env,
    },
  });
  if (res.status !== expectedStatus) {
    throw new Error(
      `pod ${args.join(' ')} → status ${res.status}（期望 ${expectedStatus}）\n${res.stdout}${res.stderr}`,
    );
  }
  return { out: res.stdout + res.stderr, stdout: res.stdout, stderr: res.stderr, status: res.status };
}

function writePolicy(p: Policy): void {
  writeFileSync(policyPath, JSON.stringify(p, null, 2));
}

const strongPolicy: Policy = {
  version: '0.2.0',
  agent: 'agent-a',
  defaultDecision: 'deny',
  servers: {
    filesystem: { allow: ['read_file'], approve: ['write_file'], deny: ['delete_file'] },
  },
  secrets: DEFAULT_SECRET_RULES,
};

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'pod-redteam-'));
  mkdirSync(join(root, 'audit'), { recursive: true });
  auditDir = join(root, 'audit');
  policyPath = join(root, 'policy.json');
  llmConfigPath = join(root, 'llm.json');
  outDir = join(root, 'out');
  writePolicy(strongPolicy);
});

describe('pod redteam — 离线（无模型）', () => {
  it('产出报告 / 场景 / 结果三份文件，并打印摘要', () => {
    const { stdout } = run(['redteam', '--policy', policyPath, '--rules', join(root, 'rules.json'), '--audit-dir', auditDir, '--out', outDir]);
    expect(stdout).toContain('pod redteam — 策略红队报告');
    expect(stdout).toContain('场景总数');
    for (const f of ['redteam-report.md', 'redteam.json', 'scenarios.json']) {
      expect(existsSync(join(outDir, f)), f).toBe(true);
    }
  });

  it('策略的密钥防线有效时，T2 场景全部被挡住', () => {
    const { stdout } = run(['redteam', '--policy', policyPath, '--rules', join(root, 'rules.json'), '--audit-dir', auditDir, '--out', outDir]);
    expect(stdout).toContain('secret-read:filesystem.read_file:~/.ssh/id_rsa');
    expect(stdout).toMatch(/\| ✅ 挡住 \|/);
  });

  it('存在高危绕过时退出码 1（可挂 CI）', () => {
    // defaultDecision=allow 让 fail-closed 那条场景直接漏掉
    writePolicy({ ...strongPolicy, defaultDecision: 'allow' });
    const { stdout } = run(['redteam', '--policy', policyPath, '--rules', join(root, 'rules.json'), '--audit-dir', auditDir, '--out', outDir], 1);
    expect(stdout).toContain('unregistered-server');
    expect(stdout).toContain('🔴 high');
  });

  it('报告写明证明力的边界，不宣称策略安全', () => {
    run(['redteam', '--policy', policyPath, '--rules', join(root, 'rules.json'), '--audit-dir', auditDir, '--out', outDir]);
    const md = readFileSync(join(outDir, 'redteam-report.md'), 'utf8');
    expect(md).toContain('不说"策略是安全的"');
    expect(md).toContain('没有真的调用任何 MCP server');
  });
});

describe('pod redteam — 出网面与模型路径', () => {
  it('--export-surface 只导出权限面：没有参数、路径、审计', () => {
    const surfacePath = join(root, 'surface.json');
    run(['redteam', '--policy', policyPath, '--rules', join(root, 'rules.json'), '--audit-dir', auditDir, '--out', outDir, '--export-surface', surfacePath]);
    const surface = JSON.parse(readFileSync(surfacePath, 'utf8'));
    expect(surface.tools.map((t: { tool: string }) => t.tool)).toEqual(['delete_file', 'read_file', 'write_file']);
    expect(surface.tools[0]).toHaveProperty('verdicts');
    // 出网面里不该出现任何路径或参数
    const raw = readFileSync(surfacePath, 'utf8');
    expect(raw).not.toContain('.ssh');
    expect(raw).not.toContain('args');
  });

  it('--llm + mock provider（离线）：场景被接收，调用写入审计链 kind=llm-call', () => {
    run([
      'redteam', '--policy', policyPath, '--rules', join(root, 'rules.json'),
      '--audit-dir', auditDir, '--out', outDir, '--llm', '--provider', 'mock',
    ]);
    const report = JSON.parse(readFileSync(join(outDir, 'redteam.json'), 'utf8'));
    expect(report.report.notes.join()).toContain('接收 2 条，丢弃 0 条');
    expect(report.report.results.some((r: { scenario: { id: string } }) => r.scenario.id === 'llm-mock-secret-read')).toBe(true);

    const control = readFileSync(join(auditDir, '_control/control.jsonl'), 'utf8');
    expect(control).toContain('llm:redteam.scenarios:mock/mock-1:ok');
    // 留痕里不出现 prompt 正文
    expect(control).not.toContain('filesystem.read_file [');
  });

  it('未配置模型时给出人话错误，不静默回落', () => {
    const res = run(
      ['redteam', '--policy', policyPath, '--rules', join(root, 'rules.json'), '--audit-dir', auditDir, '--out', outDir, '--llm'],
      1,
      { POD_LLM_CONFIG: join(root, 'does-not-exist.json') },
    );
    expect(res.out).toContain('未配置模型 Provider');
    expect(res.out).toContain('mock');
  });

  it('mock provider 无需 key，也不会真的发请求', () => {
    writeFileSync(llmConfigPath, JSON.stringify({ provider: 'mock' }));
    // 日志走 stderr（stdout 留给报告本体），所以断言合并输出
    const { out } = run(['redteam', '--policy', policyPath, '--rules', join(root, 'rules.json'), '--audit-dir', auditDir, '--out', outDir, '--llm']);
    expect(out).toContain('离线模拟，不发请求');
  });
});

describe('pod redteam — 外部场景文件', () => {
  it('编造的 server/tool 被丢弃并计入报告，不会刷高"挡住"计数', () => {
    const scenariosPath = join(root, 'external.json');
    writeFileSync(
      scenariosPath,
      JSON.stringify([
        { server: 'made-up', tool: 'steal', expect: 'deny' },
        { server: 'filesystem', tool: 'read_file', expect: 'deny', args: { path: '~/.ssh/id_rsa' }, intent: '读私钥' },
      ]),
    );
    const { stdout } = run([
      'redteam', '--policy', policyPath, '--rules', join(root, 'rules.json'),
      '--audit-dir', auditDir, '--out', outDir, '--scenarios', scenariosPath,
    ]);
    const report = JSON.parse(readFileSync(join(outDir, 'redteam.json'), 'utf8'));
    expect(report.rejected).toHaveLength(1);
    expect(report.rejected[0].reason).toContain('不在策略里');
    expect(report.report.notes.join()).toContain('接收 1 条，丢弃 1 条');
    // 接收的那条确实进了场景表（intent 只在"绕过项"里渲染，所以查 JSON）
    expect(report.report.results.some((r: { scenario: { intent: string } }) => r.scenario.intent === '读私钥')).toBe(true);
    expect(stdout).toContain('场景总数');
  });

  it('--scenarios 可离线复跑，结论不因复跑而改变', () => {
    const first = run([
      'redteam', '--policy', policyPath, '--rules', join(root, 'rules.json'),
      '--audit-dir', auditDir, '--out', outDir, '--json',
    ]);
    const parsed = JSON.parse(first.stdout);
    expect(parsed.total).toBeGreaterThan(0);

    const replay = run([
      'redteam', '--policy', policyPath, '--rules', join(root, 'rules.json'),
      '--audit-dir', auditDir, '--out', join(root, 'out2'),
      '--scenarios', join(outDir, 'scenarios.json'), '--json',
    ]);
    const replayParsed = JSON.parse(replay.stdout);
    // 文件里的场景被并入（内置那批也仍会重新生成），所以总数增加
    expect(replayParsed.total).toBeGreaterThan(parsed.total);
    // 结论不受复跑影响——同一份策略 + 同一批场景 = 同样的绕过数
    expect(replayParsed.bypassed).toBe(parsed.bypassed);
    // 合成的 fail-closed 探针（未登记 server）按规则被丢弃：这正是防"人造挡住"的那条闸门
    const replayReport = JSON.parse(readFileSync(join(root, 'out2', 'redteam.json'), 'utf8'));
    expect(replayReport.rejected.some((r: { reason: string }) => r.reason.includes('不在策略里'))).toBe(true);
  });
});
