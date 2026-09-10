import { describe, expect, it } from 'vitest';
import type { Policy } from '@podsec/policy';
import { suggestChainDiff, suggestDiff } from './diff.js';
import type { ToxicGroup, ToxicPath } from './types.js';

const policy: Policy = {
  version: '0.1.0',
  agent: 'a',
  defaultDecision: 'deny',
  servers: { s: { allow: ['read_file', 'send_email'] } },
};

const path: ToxicPath = {
  id: 'path-001',
  kind: 'intra-agent',
  rule: 'exfiltration',
  severity: 'high',
  confidence: 0.7,
  source: { agent: 'a', server: 's', tool: 'read_file', capability: 'read-secret', confidence: 0.7 },
  sink: { agent: 'a', server: 's', tool: 'send_email', capability: 'external-communication', confidence: 0.8 },
  amplifier: null,
  evidence: [],
  explain: '',
  suggested_diff: null,
};

describe('suggestDiff', () => {
  it('tightens the sink from allow to approve first', () => {
    expect(suggestDiff(path, policy)).toMatchObject({ target: 's.send_email', from: 'allow', to: 'approve' });
  });

  it('returns null when the sink is already denied', () => {
    const denied: Policy = { ...policy, servers: { s: { deny: ['send_email'] } } };
    expect(suggestDiff(path, denied)).toBeNull();
  });
});

describe('suggestChainDiff', () => {
  const group: ToxicGroup = {
    id: 'chain-001',
    rule: 'exfiltration',
    severity: 'high',
    sourceCapability: 'read-secret',
    sinkCapability: 'external-communication',
    count: 2,
    intraAgent: 2,
    crossAgent: 0,
    sourceTools: ['a.read_file'],
    sinkTools: ['a.send_email'],
    sourceEndpoints: [path.source],
    sinkEndpoints: [path.sink],
    sample: path,
  };

  it('tightens the smaller side (sink) and reports covered paths', () => {
    const diff = suggestChainDiff(group, policy);
    expect(diff?.strategy).toBe('tighten-sinks');
    expect(diff?.breaks_paths).toBe(2);
    expect(diff?.changes[0]).toMatchObject({ target: 's.send_email', from: 'allow', to: 'approve' });
  });

  it('returns null when the chosen side is already denied', () => {
    const denied: Policy = { ...policy, servers: { s: { deny: ['send_email'] } } };
    expect(suggestChainDiff(group, denied)).toBeNull();
  });

  it('degrades to a capability-level recommendation when no small cut exists', () => {
    const manySources = ['r1', 'r2', 'r3', 'r4'].map((tool) => ({
      agent: 'a',
      server: 's',
      tool,
      capability: 'read-secret' as const,
      confidence: 0.8,
    }));
    const manySinks = ['a', 'b', 'c', 'd'].map((tool) => ({
      agent: 'a',
      server: 's',
      tool,
      capability: 'external-communication' as const,
      confidence: 0.8,
    }));
    const diff = suggestChainDiff(
      {
        ...group,
        sourceEndpoints: manySources,
        sinkEndpoints: manySinks,
        sourceTools: manySources.map((e) => e.tool),
        sinkTools: manySinks.map((e) => e.tool),
      },
      policy,
    );
    expect(diff?.strategy).toBe('capability-level');
    expect(diff?.capability_recommendation?.needs_capability_policy).toBe(true);
    expect(diff?.changes).toHaveLength(3);
  });
});
