import { describe, expect, it } from 'vitest';
import { baselineForAgent, decideFromCapabilities } from './baseline.js';
import type { CapabilityGraph } from './types.js';

function graph(source: 'static' | 'observed', tools: Array<{ agent: string; server: string; tool: string; capabilities?: string[]; calls?: number }>): CapabilityGraph {
  const nodes = [];
  const edges = [];
  for (const t of tools) {
    nodes.push({ id: `agent:${t.agent}`, type: 'agent' as const, agent: t.agent });
    nodes.push({ id: `server:${t.server}`, type: 'server' as const, server: t.server });
    nodes.push({ id: `tool:${t.server}.${t.tool}`, type: 'tool' as const, server: t.server, tool: t.tool, calls: t.calls });
    edges.push({ from: `agent:${t.agent}`, to: `server:${t.server}`, type: 'connects' as const });
    edges.push({ from: `server:${t.server}`, to: `tool:${t.server}.${t.tool}`, type: 'exposes' as const });
    for (const capability of t.capabilities ?? []) {
      edges.push({ from: `tool:${t.server}.${t.tool}`, to: `capability:${capability}`, type: 'has_capability' as const });
    }
  }
  return {
    schema_version: '0.1.0',
    source,
    generated_at: '2026-09-10T00:00:00.000Z',
    meta: { tool_version: '0.1.0', config_fingerprint: 'x', warnings: [] },
    nodes,
    edges,
  };
}

describe('decideFromCapabilities', () => {
  it('maps destructive→deny, secret/write→approve, read-only→allow', () => {
    expect(decideFromCapabilities(['destructive-write'])).toBe('deny');
    expect(decideFromCapabilities(['read-secret'])).toBe('approve');
    expect(decideFromCapabilities(['exec'])).toBe('approve');
    expect(decideFromCapabilities([])).toBe('approve');
    expect(decideFromCapabilities(['read-private-data'])).toBe('allow');
  });
});

describe('baselineForAgent', () => {
  it('keeps observed tools, decides by capability, and omits over-privileged tools', () => {
    const potential = graph('static', [
      { agent: 'a', server: 's', tool: 'read_file', capabilities: ['read-secret'] },
      { agent: 'a', server: 's', tool: 'send_email', capabilities: ['external-communication'] },
      { agent: 'a', server: 's', tool: 'delete_file', capabilities: ['destructive-write'] },
      { agent: 'a', server: 's', tool: 'unused_tool', capabilities: ['external-communication'] },
    ]);
    const observed = graph('observed', [
      { agent: 'a', server: 's', tool: 'read_file', capabilities: ['read-secret'], calls: 10 },
      { agent: 'a', server: 's', tool: 'send_email', capabilities: ['external-communication'], calls: 2 },
      { agent: 'a', server: 's', tool: 'shadow_tool', calls: 1 },
    ]);
    const result = baselineForAgent(potential, observed, { agent: 'a' });
    const serverPolicy = result.policy.servers!.s!;
    expect(serverPolicy.approve).toEqual(['read_file', 'send_email', 'shadow_tool']);
    expect(serverPolicy.deny).toBeUndefined();
    expect(result.overPrivileged.map((e) => e.tool)).toEqual(['delete_file', 'unused_tool']);
    expect(result.shadow.map((e) => e.tool)).toEqual(['shadow_tool']);
    expect(result.counts).toMatchObject({ allow: 0, approve: 3, omitted: 2 });
  });
});
