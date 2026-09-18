import { describe, expect, it } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadAuditFile } from '@podsec/audit';
import { loadAgentIdentity } from '@podsec/identity';
import {
  enrollAgent,
  enrollmentStatePath,
  forgetAgent,
  readEnrollment,
} from './enroll.js';

function makePodHome(): string {
  return join(mkdtempSync(join(tmpdir(), 'pod-enroll-')), '.pod');
}

/**
 * 控制平面事件落在**被纳管的 agent** 的链上（不是机器级的 _control）：
 * pod sync 按绑定 agent 过滤事件，写进 _control 就永远上不了云。
 */
function controlEntries(podHome: string, agent = 'claude-code') {
  const path = join(podHome, 'audit', agent, 'control.jsonl');
  if (!existsSync(path)) return [];
  return loadAuditFile(path, 'control').entries;
}

describe('enrollAgent', () => {
  it('建身份 + 零权限策略 + 审计目录，并把两条事件写进哈希链', () => {
    const podHome = makePodHome();
    const result = enrollAgent({ podHome, harness: 'claude-code', agent: 'claude-code' });

    expect(result.changed).toEqual({ identity: true, policy: true, auditDir: true });
    expect(result.alreadyManaged).toBe(false);
    expect(existsSync(join(podHome, 'identity/claude-code/private.pem'))).toBe(true);
    expect(existsSync(join(podHome, 'identity/claude-code/identity.json'))).toBe(true);
    expect(existsSync(join(podHome, 'audit/claude-code'))).toBe(true);
    expect(existsSync(join(podHome, 'policies/claude-code.json'))).toBe(true);

    // 零权限起点：未登记 server 一律拒绝（不是"先放开再收紧"）
    const policy = JSON.parse(readFileSync(join(podHome, 'policies/claude-code.json'), 'utf8')) as {
      agent: string;
      defaultDecision: string;
      servers: Record<string, unknown>;
    };
    expect(policy.agent).toBe('claude-code');
    expect(policy.defaultDecision).toBe('deny');
    expect(Object.keys(policy.servers)).toHaveLength(0);

    const entries = controlEntries(podHome);
    expect(entries.map((e) => e.kind)).toEqual(['identity', 'config-change']);
    expect(entries[0]!.reason).toContain('console:enroll:claude-code');
    expect(entries[0]!.server).toBe('control');
  });

  it('幂等：第二次不再改动，也不覆盖已存在的策略', () => {
    const podHome = makePodHome();
    enrollAgent({ podHome, harness: 'codex', agent: 'codex' });
    const policyPath = join(podHome, 'policies/codex.json');
    const edited = JSON.parse(readFileSync(policyPath, 'utf8')) as Record<string, unknown>;
    edited.servers = { filesystem: { allow: ['read_file'] } };
    writeFileSync(policyPath, JSON.stringify(edited, null, 2), 'utf8');

    const second = enrollAgent({ podHome, harness: 'codex', agent: 'codex' });
    expect(second.alreadyManaged).toBe(true);
    expect(second.changed).toEqual({ identity: false, policy: false, auditDir: false });
    // 用户改过的策略必须原样保留
    const after = JSON.parse(readFileSync(policyPath, 'utf8')) as { servers: Record<string, unknown> };
    expect(Object.keys(after.servers)).toEqual(['filesystem']);
    expect(controlEntries(podHome, 'codex')).toHaveLength(2); // 没有多写事件
  });

  it('已有策略绑定同名 agent 时不新建文件（避免一个 agent 两份策略）', () => {
    const podHome = makePodHome();
    mkdirSync(join(podHome, 'policies'), { recursive: true });
    writeFileSync(
      join(podHome, 'policies/baseline-cursor.json'),
      JSON.stringify({ version: '0.1.0', agent: 'cursor', servers: {} }),
      'utf8',
    );
    const result = enrollAgent({ podHome, harness: 'cursor', agent: 'cursor' });
    expect(result.changed.policy).toBe(false);
    expect(result.policyFile).toBe('baseline-cursor.json');
    expect(existsSync(join(podHome, 'policies/cursor.json'))).toBe(false);
  });

  it('非法 agent 名直接抛错，不留半截产物', () => {
    const podHome = makePodHome();
    for (const bad of ['../evil', 'has space', '', 'a/b', '.']) {
      expect(() => enrollAgent({ podHome, harness: 'codex', agent: bad })).toThrow();
    }
    expect(existsSync(join(podHome, 'policies'))).toBe(false);
  });

  it('把"纳管 ≠ 拦住"写进 notes（有 server 绕过网关时）', () => {
    const podHome = makePodHome();
    const result = enrollAgent({
      podHome,
      harness: 'codex',
      agent: 'codex',
      serverSummary: { total: 3, behindGateway: 1 },
    });
    expect(result.notes.join(' ')).toContain('不会拦住');
    expect(result.notes.join(' ')).toContain('不改动 harness 的配置');
  });

  it('台账记录纳管来源与身份指纹', () => {
    const podHome = makePodHome();
    const result = enrollAgent({ podHome, harness: 'codex', agent: 'codex', enrolledBy: 'pod ui' });
    const state = readEnrollment(enrollmentStatePath(podHome));
    const record = state.agents['codex']!;
    expect(record.harness).toBe('codex');
    expect(record.enrolledBy).toBe('pod ui');
    expect(record.identityFingerprint).toBe(result.identityFingerprint);
    expect(loadAgentIdentity('codex', join(podHome, 'identity'))?.fingerprint).toBe(
      result.identityFingerprint,
    );
  });
});

describe('forgetAgent', () => {
  it('删掉纳管创建的策略，默认保留身份，并记一条审计', () => {
    const podHome = makePodHome();
    enrollAgent({ podHome, harness: 'codex', agent: 'codex' });
    const result = forgetAgent({ podHome, agent: 'codex' });

    expect(result.found).toBe(true);
    expect(result.removed.policy).toBe(true);
    expect(result.removed.identity).toBe(false);
    expect(existsSync(join(podHome, 'policies/codex.json'))).toBe(false);
    expect(existsSync(join(podHome, 'identity/codex/private.pem'))).toBe(true);
    expect(readEnrollment(enrollmentStatePath(podHome)).agents['codex']).toBeUndefined();
    expect(controlEntries(podHome, 'codex').at(-1)!.reason).toContain('console:forget:codex');
  });

  it('--purge-identity 才删身份', () => {
    const podHome = makePodHome();
    enrollAgent({ podHome, harness: 'codex', agent: 'codex' });
    const result = forgetAgent({ podHome, agent: 'codex', purgeIdentity: true });
    expect(result.removed.identity).toBe(true);
    expect(existsSync(join(podHome, 'identity/codex'))).toBe(false);
  });

  it('不动用户自己的策略（只有纳管创建的才删）', () => {
    const podHome = makePodHome();
    mkdirSync(join(podHome, 'policies'), { recursive: true });
    writeFileSync(
      join(podHome, 'policies/mine.json'),
      JSON.stringify({ version: '0.1.0', agent: 'mine', servers: {} }),
      'utf8',
    );
    enrollAgent({ podHome, harness: 'codex', agent: 'mine' });
    const result = forgetAgent({ podHome, agent: 'mine' });
    expect(result.removed.policy).toBe(false);
    expect(existsSync(join(podHome, 'policies/mine.json'))).toBe(true);
    expect(result.notes.join(' ')).toContain('不删用户自己的策略');
  });

  it('没有纳管记录时不乱删', () => {
    const podHome = makePodHome();
    const result = forgetAgent({ podHome, agent: 'stranger' });
    expect(result.found).toBe(false);
    expect(result.removed).toEqual({ policy: false, identity: false });
  });
});
