import { describe, expect, it } from 'vitest';
import type { CapabilityGraph } from './types.js';
import { findToxicPaths } from './toxic.js';

function graphWithAgents(): CapabilityGraph {
  const nodes = [
    { id: 'agent:a', type: 'agent' as const, agent: 'a' },
    { id: 'agent:b', type: 'agent' as const, agent: 'b' },
    { id: 'server:s', type: 'server' as const, server: 's' },
    { id: 'tool:s.read_file', type: 'tool' as const, server: 's', tool: 'read_file' },
    { id: 'tool:s.send_email', type: 'tool' as const, server: 's', tool: 'send_email' },
    { id: 'tool:s.execute_command', type: 'tool' as const, server: 's', tool: 'execute_command' },
    { id: 'tool:s.http_request', type: 'tool' as const, server: 's', tool: 'http_request' },
    { id: 'tool:s.delete_file', type: 'tool' as const, server: 's', tool: 'delete_file', writeContext: true },
  ];
  const edges = [
    { from: 'agent:a', to: 'server:s', type: 'connects' as const },
    { from: 'agent:b', to: 'server:s', type: 'connects' as const },
    { from: 'server:s', to: 'tool:s.read_file', type: 'exposes' as const },
    { from: 'server:s', to: 'tool:s.send_email', type: 'exposes' as const },
    { from: 'server:s', to: 'tool:s.execute_command', type: 'exposes' as const },
    { from: 'server:s', to: 'tool:s.http_request', type: 'exposes' as const },
    { from: 'server:s', to: 'tool:s.delete_file', type: 'exposes' as const },
    { from: 'tool:s.read_file', to: 'capability:read-secret', type: 'has_capability' as const, confidence: 0.7, evidence: ['name'] },
    { from: 'tool:s.send_email', to: 'capability:external-communication', type: 'has_capability' as const, confidence: 0.8, evidence: ['name'] },
    { from: 'tool:s.execute_command', to: 'capability:exec', type: 'has_capability' as const, confidence: 0.9, evidence: ['name'] },
    { from: 'tool:s.http_request', to: 'capability:read-untrusted-input', type: 'has_capability' as const, confidence: 0.5, evidence: ['schema'] },
    { from: 'tool:s.delete_file', to: 'capability:destructive-write', type: 'has_capability' as const, confidence: 0.9, evidence: ['name'] },
  ];
  return {
    schema_version: '0.1.0',
    source: 'static',
    generated_at: '2026-09-09T00:00:00.000Z',
    meta: { tool_version: '0.1.0', config_fingerprint: 'sha256:x', warnings: [] },
    nodes,
    edges,
  };
}

describe('findToxicPaths', () => {
  it('finds intra-agent exfiltration and injection-exec', () => {
    const { paths } = findToxicPaths(graphWithAgents(), { minConfidence: 0.4 });
    const rules = paths.map((p) => p.rule);
    expect(rules).toContain('exfiltration');
    expect(rules).toContain('injection-exec');
    expect(rules).toContain('destruction');
  });

  it('does not pair across agents by default, but does with crossAgent', () => {
    const graph = graphWithAgents();
    const intra = findToxicPaths(graph, { minConfidence: 0.4 });
    expect(intra.paths.every((p) => p.kind === 'intra-agent')).toBe(true);
    const cross = findToxicPaths(graph, { minConfidence: 0.4, crossAgent: true });
    expect(cross.paths.some((p) => p.kind === 'cross-agent')).toBe(true);
  });

  it('filters by minConfidence and caps maxPaths while counting total', () => {
    const { paths, total } = findToxicPaths(graphWithAgents(), { minConfidence: 0.4, maxPaths: 1 });
    expect(paths).toHaveLength(1);
    expect(total).toBeGreaterThan(1);
  });

  it('groups paths by source→sink capability and counts every path', () => {
    const { groups, total } = findToxicPaths(graphWithAgents(), { minConfidence: 0.4, crossAgent: true });
    expect(groups.length).toBeGreaterThan(0);
    expect(groups.some((g) => g.rule === 'exfiltration')).toBe(true);
    expect(groups.reduce((sum, g) => sum + g.count, 0)).toBe(total);
  });

  it('assigns chain ids and unique endpoints', () => {
    const { groups } = findToxicPaths(graphWithAgents(), { minConfidence: 0.4 });
    expect(groups[0]!.id).toMatch(/^chain-\d{3}$/);
    expect(groups[0]!.sourceEndpoints.length).toBeGreaterThan(0);
    expect(groups[0]!.sinkEndpoints.length).toBeGreaterThan(0);
  });
});
