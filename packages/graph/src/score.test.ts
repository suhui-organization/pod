import { describe, expect, it } from 'vitest';
import { scoreToxicGroups } from './score.js';
import type { ToxicGroup, ToxicPath } from './types.js';

const sample: ToxicPath = {
  id: 'path-001',
  kind: 'cross-agent',
  rule: 'exfiltration',
  severity: 'high',
  confidence: 0.7,
  source: { agent: 'a', server: 's', tool: 'read_file', capability: 'read-secret', confidence: 0.7 },
  sink: { agent: 'b', server: 's', tool: 'execute_command', capability: 'exec', confidence: 0.9 },
  amplifier: null,
  evidence: [],
  explain: '',
  suggested_diff: null,
};

function group(overrides: Partial<ToxicGroup>): ToxicGroup {
  return {
    id: 'chain-001',
    rule: 'exfiltration',
    severity: 'high',
    sourceCapability: 'read-secret',
    sinkCapability: 'exec',
    count: 100,
    intraAgent: 0,
    crossAgent: 100,
    sourceTools: ['a.read_file'],
    sinkTools: ['b.execute_command'],
    sourceEndpoints: [sample.source],
    sinkEndpoints: [sample.sink],
    sample,
    ...overrides,
  };
}

describe('scoreToxicGroups', () => {
  it('ranks cross-agent secret→exec above intra untrusted→external', () => {
    const high = group({});
    const low = group({
      rule: 'injection-exfil',
      severity: 'medium',
      sourceCapability: 'read-untrusted-input',
      sinkCapability: 'external-communication',
      count: 5,
      crossAgent: 0,
      intraAgent: 5,
    });
    const scored = scoreToxicGroups([low, high]);
    expect(scored[0]!.rule).toBe('exfiltration');
    expect(scored[0]!.score).toBeGreaterThan(scored[1]!.score);
    expect(scored[0]!.score_reasons.join(' ')).toContain('cross-agent');
  });

  it('keeps a bounded raw score and a risk label', () => {
    const scored = scoreToxicGroups([group({ count: 100000 })])[0]!;
    expect(scored.score).toBeLessThanOrEqual(200);
    expect(['critical', 'high', 'medium', 'low']).toContain(scored.risk);
    expect(scored.score_reasons.length).toBeGreaterThan(0);
  });
});
