import { describe, expect, it } from 'vitest';
import { renderToxicReport } from './report.js';
import type { ScoredToxicGroup } from './score.js';
import type { CapabilityGraph, ToxicPath } from './types.js';

const graph: CapabilityGraph = {
  schema_version: '0.1.0',
  source: 'static',
  generated_at: '2026-09-09T00:00:00.000Z',
  meta: { tool_version: '0.1.0', config_fingerprint: 'sha256:x', warnings: [] },
  nodes: [],
  edges: [],
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
  evidence: ['e1'],
  explain: 'why',
  suggested_diff: null,
};

describe('renderToxicReport', () => {
  it('renders path id, rule and counts', () => {
    const text = renderToxicReport({ graph, paths: [path], total: 1, maxPaths: 20, minConfidence: 0.5 });
    expect(text).toContain('path-001');
    expect(text).toContain('exfiltration');
    expect(text).toContain('高危（1）');
  });

  it('renders a clear no-path message', () => {
    const text = renderToxicReport({ graph, paths: [], total: 0, maxPaths: 20, minConfidence: 0.5 });
    expect(text).toContain('未发现毒性路径');
  });

  it('renders aggregated chains when groups are provided', () => {
    const groups: ScoredToxicGroup[] = [
      {
        id: 'chain-001',
        rule: 'exfiltration',
        severity: 'high',
        sourceCapability: 'read-secret',
        sinkCapability: 'external-communication',
        count: 3,
        intraAgent: 2,
        crossAgent: 1,
        sourceTools: ['a.read_file'],
        sinkTools: ['a.send_email'],
        sourceEndpoints: [path.source],
        sinkEndpoints: [path.sink],
        sample: path,
        score: 92,
        risk: 'high',
        score_reasons: ['rule exfiltration +40', 'cross-agent 1/3 +15'],
      },
    ];
    const text = renderToxicReport({ graph, paths: [path], total: 3, maxPaths: 20, minConfidence: 0.5, groups });
    expect(text).toContain('风险排序');
    expect(text).toContain('92');
  });
});
