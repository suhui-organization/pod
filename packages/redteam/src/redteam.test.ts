import { describe, expect, it } from 'vitest';
import { DEFAULT_RULES, DEFAULT_SECRET_RULES, type Policy, type RuleSet } from '@podsec/policy';
import { generateBaselineScenarios, toolInventory, validateScenarios } from './generate.js';
import { buildReport, renderRedteamReport } from './run.js';

function policy(overrides: Partial<Policy> = {}): Policy {
  return {
    version: '0.1.0',
    agent: 'agent-a',
    defaultDecision: 'deny',
    servers: {
      filesystem: { allow: ['read_file', 'list_directory'], approve: ['write_file'], deny: ['delete_file'] },
      github: { allow: ['get_issue'], approve: ['create_issue'] },
    },
    secrets: DEFAULT_SECRET_RULES,
    ...overrides,
  };
}

describe('内置场景生成', () => {
  it('工具清单取 allow/approve/deny 三张表的并集', () => {
    expect(toolInventory(policy()).map((t) => `${t.server}.${t.tool}`)).toEqual([
      'filesystem.delete_file',
      'filesystem.list_directory',
      'filesystem.read_file',
      'filesystem.write_file',
      'github.create_issue',
      'github.get_issue',
    ]);
  });

  it('读取类工具 × 敏感路径形状都生成了场景；写类与破坏类各一条', () => {
    const { scenarios } = generateBaselineScenarios({ policy: policy() });
    const ids = scenarios.map((s) => s.id);
    // read_file / list_directory / get_issue 是读取面，各有若干敏感路径形状
    expect(ids.some((id) => id.startsWith('secret-read:filesystem.read_file:'))).toBe(true);
    expect(ids.some((id) => id.startsWith('secret-read:github.get_issue:'))).toBe(true);
    expect(ids).toContain('write:filesystem.write_file');
    expect(ids).toContain('destructive:filesystem.delete_file');
    expect(ids).toContain('unregistered-server');
  });

  it('egress 未启用时不出网场景，并如实写明原因', () => {
    const { scenarios, notes } = generateBaselineScenarios({ policy: policy() });
    expect(scenarios.some((s) => s.id.startsWith('egress-exfil:'))).toBe(false);
    expect(notes.join()).toContain('egress 判定未启用');
  });

  it('egress 启用且配了 denyHosts 时生成出网场景（含后缀匹配写法）', () => {
    const rules: RuleSet = {
      ...structuredClone(DEFAULT_RULES),
      egress: { enabled: true, allowHosts: [], denyHosts: ['.evil.com'], defaultDecision: 'allow' },
    };
    const { scenarios } = generateBaselineScenarios({ policy: policy(), rules });
    const exfil = scenarios.find((s) => s.id.startsWith('egress-exfil:'));
    expect(exfil).toBeDefined();
    expect(JSON.stringify(exfil!.args)).toContain('redteam.evil.com');
  });
});

describe('确定性执行与判定', () => {
  it('配了敏感路径防线时，读取密钥的场景全部被挡住', () => {
    const report = buildReport({ policy: policy(), rules: DEFAULT_RULES, scenarios: generateBaselineScenarios({ policy: policy() }).scenarios });
    const secretReads = report.results.filter((r) => r.scenario.id.startsWith('secret-read:'));
    expect(secretReads.length).toBeGreaterThan(0);
    expect(secretReads.every((r) => r.outcome === 'blocked')).toBe(true);
    expect(secretReads.every((r) => r.matched === 'secrets-input')).toBe(true);
  });

  it('策略没配 secrets 时，同一个场景变成 high 级绕过', () => {
    const weak = policy({ secrets: undefined });
    const { scenarios } = generateBaselineScenarios({ policy: weak });
    const report = buildReport({ policy: weak, rules: DEFAULT_RULES, scenarios });
    const bypassed = report.findings.filter((f) => f.scenario.id.startsWith('secret-read:filesystem.read_file:'));
    expect(bypassed.length).toBeGreaterThan(0);
    expect(bypassed.every((f) => f.severity === 'high')).toBe(true);
    expect(bypassed[0]!.actual).toBe('allow');
  });

  it('defaultDecision=allow 时 fail-closed 场景被绕过（整条防线是空的）', () => {
    const open = policy({ defaultDecision: 'allow' });
    const report = buildReport({ policy: open, rules: DEFAULT_RULES, scenarios: generateBaselineScenarios({ policy: open }).scenarios });
    const prob = report.findings.find((f) => f.scenario.id === 'unregistered-server');
    expect(prob).toBeDefined();
    expect(prob!.actual).toBe('allow');
    expect(prob!.severity).toBe('high');
  });

  it('破坏性操作走审批即算挡住，直接放行算绕过', () => {
    const withDeny = policy();
    const r1 = buildReport({ policy: withDeny, rules: DEFAULT_RULES, scenarios: generateBaselineScenarios({ policy: withDeny }).scenarios });
    expect(r1.findings.find((f) => f.scenario.id === 'destructive:filesystem.delete_file')).toBeUndefined();

    const wideOpen = policy({
      servers: { filesystem: { allow: ['delete_file', 'read_file'] } },
      secrets: DEFAULT_SECRET_RULES,
    });
    const r2 = buildReport({ policy: wideOpen, rules: DEFAULT_RULES, scenarios: generateBaselineScenarios({ policy: wideOpen }).scenarios });
    const found = r2.findings.find((f) => f.scenario.id === 'destructive:filesystem.delete_file');
    expect(found?.severity).toBe('medium');
  });

  it('egress 场景走的是与网关同一条流水线：denyHosts 命中即挡住', () => {
    const rules: RuleSet = {
      ...structuredClone(DEFAULT_RULES),
      egress: { enabled: true, allowHosts: [], denyHosts: ['.evil.com'], defaultDecision: 'allow' },
    };
    const p = policy();
    const report = buildReport({ policy: p, rules, scenarios: generateBaselineScenarios({ policy: p, rules }).scenarios });
    const exfil = report.results.find((r) => r.scenario.id.startsWith('egress-exfil:'));
    expect(exfil?.outcome).toBe('blocked');
    expect(exfil?.reason).toContain('denyHosts');
  });

  it('同样的输入两次跑出同样的结论（可进 CI 当回归测试）', () => {
    const p = policy();
    const scenarios = generateBaselineScenarios({ policy: p }).scenarios;
    const a = buildReport({ policy: p, rules: DEFAULT_RULES, scenarios });
    const b = buildReport({ policy: p, rules: DEFAULT_RULES, scenarios });
    expect(a.results.map((r) => `${r.scenario.id}=${r.actual}`)).toEqual(
      b.results.map((r) => `${r.scenario.id}=${r.actual}`),
    );
  });
});

describe('外部场景校验（模型产出的闸门）', () => {
  it('编造的 server / tool 被丢弃——否则 fail-closed 会把人造场景刷成"挡住"', () => {
    const { accepted, rejected } = validateScenarios(
      [
        { server: 'made-up-server', tool: 'steal', expect: 'deny' },
        { server: 'filesystem', tool: 'made-up-tool', expect: 'deny' },
        { server: 'filesystem', tool: 'read_file', expect: 'deny', args: { path: '~/.ssh/id_rsa' } },
      ],
      policy(),
    );
    expect(accepted).toHaveLength(1);
    expect(accepted[0]!.tool).toBe('read_file');
    expect(rejected).toHaveLength(2);
    expect(rejected[0]!.reason).toContain('不在策略里');
    expect(rejected[1]!.reason).toContain('未登记');
  });

  it('expect 不是三态之一、或根本不是数组时被拒', () => {
    const bad = validateScenarios([{ server: 'filesystem', tool: 'read_file', expect: 'block' }], policy());
    expect(bad.accepted).toHaveLength(0);
    expect(bad.rejected[0]!.reason).toContain('expect');
    expect(validateScenarios({ not: 'an array' }, policy()).rejected[0]!.reason).toContain('数组');
  });

  it('合法场景补全 id/intent/why 后可用，并标记来源为 llm', () => {
    const { accepted } = validateScenarios(
      [{ server: 'filesystem', tool: 'write_file', expect: 'approve', args: {}, why: '写操作该审批' }],
      policy(),
    );
    expect(accepted[0]).toMatchObject({ origin: 'llm', threat: 'T1', why: '写操作该审批' });
    expect(accepted[0]!.id).toContain('filesystem.write_file');
  });
});

describe('报告', () => {
  it('写明证明力的边界，不宣称"策略安全"', () => {
    const p = policy();
    const md = renderRedteamReport(
      buildReport({ policy: p, rules: DEFAULT_RULES, scenarios: generateBaselineScenarios({ policy: p }).scenarios }),
    );
    expect(md).toContain('不说"策略是安全的"');
    expect(md).toContain('没有真的调用任何 MCP server');
    expect(md).toContain('不理解编码');
  });

  it('未覆盖项出现在报告里', () => {
    const p = policy();
    const gen = generateBaselineScenarios({ policy: p });
    const md = renderRedteamReport(buildReport({ policy: p, rules: DEFAULT_RULES, scenarios: gen.scenarios, notes: gen.notes }));
    expect(md).toContain('本次未覆盖或已丢弃');
    expect(md).toContain('egress 判定未启用');
  });
});
