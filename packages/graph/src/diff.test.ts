import { describe, expect, it } from 'vitest';
import type { Policy } from '@podsec/policy';
import { suggestDiff } from './diff.js';
import type { ToxicPath } from './types.js';

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
