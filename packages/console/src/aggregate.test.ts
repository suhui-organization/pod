/**
 * Agent 资产聚合的失败模式与降级测试。
 *
 * 这些用例守护 PRODUCT.md 的第一原则（证据优先、说清楚不夸大）：
 * 数据缺失时必须明确记录缺口，而不是编造"一切正常"。
 */
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { aggregateAgents } from './aggregate.js';

const NOW = new Date('2026-09-10T12:00:00Z');

interface Fixture {
  root: string;
  podHome: string;
  home: string;
}

const created: string[] = [];

function fixture(): Fixture {
  const root = mkdtempSync(join(tmpdir(), 'pod-console-'));
  created.push(root);
  const home = join(root, 'home');
  const podHome = join(home, '.pod');
  mkdirSync(podHome, { recursive: true });
  return { root, podHome, home };
}

function writePolicy(fx: Fixture, name: string, policy: unknown): void {
  mkdirSync(join(fx.podHome, 'policies'), { recursive: true });
  writeFileSync(join(fx.podHome, 'policies', name), JSON.stringify(policy, null, 2));
}

function writeAudit(fx: Fixture, server: string, rows: unknown[]): void {
  mkdirSync(join(fx.podHome, 'audit'), { recursive: true });
  writeFileSync(
    join(fx.podHome, 'audit', `${server}.jsonl`),
    rows.map((r) => JSON.stringify(r)).join('\n') + '\n',
  );
}

function writeToxic(fx: Fixture, paths: unknown[]): void {
  mkdirSync(join(fx.podHome, 'graph'), { recursive: true });
  writeFileSync(join(fx.podHome, 'graph', 'paths.json'), JSON.stringify(paths, null, 2));
}

function auditRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    seq: 1,
    ts: '2026-09-10T11:00:00.000Z',
    agent: 'claude-code',
    session: 's1',
    server: 'filesystem',
    tool: 'read_file',
    argsHash: 'sha256:deadbeef',
    decision: 'allow',
    outcome: 'ok',
    policyVersion: '1',
    enforced: true,
    prevHash: '',
    hash: 'sha256:cafe',
    ...overrides,
  };
}

afterEach(() => {
  while (created.length > 0) {
    const dir = created.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

describe('aggregateAgents', () => {
  it('空 ~/.pod：不报错，缺口写进 notes，agents 为空', () => {
    const fx = fixture();
    const payload = aggregateAgents({ home: fx.home, podHome: fx.podHome, now: NOW });

    expect(payload.agents).toEqual([]);
    expect(payload.totals.agents).toBe(0);
    expect(payload.notes.join('\n')).toContain('未找到策略目录');
    expect(payload.notes.join('\n')).toContain('未找到审计目录');
    expect(payload.notes.join('\n')).toContain('paths.json');
  });

  it('策略 + 审计：合并成一个 agent，权限按三态计数，近 7 天活动分桶', () => {
    const fx = fixture();
    writePolicy(fx, 'claude-code.json', {
      version: '3',
      agent: 'claude-code',
      defaultDecision: 'deny',
      servers: {
        filesystem: { allow: ['read_file', 'list_dir'], deny: ['delete_file'] },
        github: { approve: ['create_pull_request'] },
      },
    });
    writeAudit(fx, 'filesystem', [
      auditRow({ seq: 1, ts: '2026-09-10T10:00:00.000Z', tool: 'read_file' }),
      auditRow({ seq: 2, ts: '2026-09-10T10:05:00.000Z', tool: 'delete_file', decision: 'deny' }),
      auditRow({ seq: 3, ts: '2026-09-04T10:05:00.000Z', tool: 'read_file' }),
    ]);

    const payload = aggregateAgents({ home: fx.home, podHome: fx.podHome, now: NOW });
    expect(payload.agents).toHaveLength(1);

    const agent = payload.agents[0]!;
    expect(agent.id).toBe('claude-code');
    expect(agent.status).toBe('active');
    expect(agent.policy?.version).toBe('3');
    expect(agent.permissions).toEqual({
      servers: 2,
      tools: 4,
      allow: 2,
      approve: 1,
      deny: 1,
    });

    expect(agent.activity.entries).toBe(3);
    expect(agent.activity.calls7d).toHaveLength(7);
    // 7 天窗口 = 09-04…09-10：09-04 落第一个桶，09-10（今天）落最后一个桶
    expect(agent.activity.calls7d[0]).toBe(1);
    expect(agent.activity.calls7d.at(-1)).toBe(2);
    expect(agent.activity.calls7dTotal).toBe(3);
    expect(agent.activity.deny7d).toBe(1);
    expect(agent.activity.lastDecision?.decision).toBe('deny');
    expect(agent.activity.lastDecision?.server).toBe('filesystem');
  });

  it('有调用无策略：标为 unobserved，并给出高危 unregistered 信号', () => {
    const fx = fixture();
    writeAudit(fx, 'shell', [auditRow({ agent: 'codex-lab', server: 'shell', tool: 'execute_command' })]);

    const payload = aggregateAgents({ home: fx.home, podHome: fx.podHome, now: NOW });
    const agent = payload.agents.find((a) => a.id === 'codex-lab');
    expect(agent?.status).toBe('unobserved');
    expect(agent?.policy).toBeNull();
    expect(agent?.risks.some((r) => r.kind === 'unregistered' && r.severity === 'high')).toBe(true);
  });

  it('敏感路径拒绝计入风险，且带出被拒的路径模式', () => {
    const fx = fixture();
    writePolicy(fx, 'p.json', { version: '1', agent: 'openclaw', servers: { filesystem: { allow: ['read_file'] } } });
    writeAudit(fx, 'filesystem', [
      auditRow({
        agent: 'openclaw',
        decision: 'deny',
        reason: 'argument hits sensitive path pattern ".env" (secrets.deny_input_paths)',
      }),
    ]);

    const payload = aggregateAgents({ home: fx.home, podHome: fx.podHome, now: NOW });
    const agent = payload.agents.find((a) => a.id === 'openclaw');
    const risk = agent?.risks.find((r) => r.kind === 'sensitive-path');
    expect(risk?.severity).toBe('high');
    expect(risk?.count).toBe(1);
    expect(risk?.detail).toContain('.env');
  });

  it('毒性链按端点 agent 归因', () => {
    const fx = fixture();
    writePolicy(fx, 'p.json', { version: '1', agent: 'claude-code', servers: {} });
    writePolicy(fx, 'q.json', { version: '1', agent: 'openclaw', servers: {} });
    writeToxic(fx, [
      {
        id: 'p1',
        kind: 'cross-agent',
        rule: 'read-secret → external-communication',
        severity: 'high',
        confidence: 0.8,
        source: { agent: 'openclaw', server: 'filesystem', tool: 'read_file', capability: 'read-secret', confidence: 0.9 },
        sink: { agent: 'claude-code', server: 'http', tool: 'post', capability: 'external-communication', confidence: 0.7 },
        amplifier: null,
        evidence: ['e1'],
        explain: 'openclaw 读到密钥，claude-code 可以外发',
        suggested_diff: null,
      },
    ]);

    const payload = aggregateAgents({ home: fx.home, podHome: fx.podHome, now: NOW });
    for (const id of ['claude-code', 'openclaw']) {
      const agent = payload.agents.find((a) => a.id === id);
      expect(agent?.risks.some((r) => r.kind === 'toxic-path' && r.severity === 'high')).toBe(true);
    }
  });

  it('坏行与坏策略文件被跳过并计入 notes，不静默吞掉', () => {
    const fx = fixture();
    writePolicy(fx, 'broken.json', { version: '1' }); // 缺 agent
    writeAudit(fx, 'filesystem', [auditRow(), 'not-json-line']);

    const payload = aggregateAgents({ home: fx.home, podHome: fx.podHome, now: NOW });
    const notes = payload.notes.join('\n');
    expect(notes).toContain('缺少 agent 字段');
    expect(notes).toContain('1 行无法解析');
  });
});
