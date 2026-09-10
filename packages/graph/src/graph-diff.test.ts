import { describe, expect, it } from 'vitest';
import { diffGraphs } from './graph-diff.js';
import type { CapabilityGraph } from './types.js';

function graph(source: 'static' | 'observed', tools: Array<{ agent: string; server: string; tool: string; capability?: string; calls?: number }>): CapabilityGraph {
  const nodes = [];
  const edges = [];
  for (const t of tools) {
    nodes.push({ id: `agent:${t.agent}`, type: 'agent' as const, agent: t.agent });
    nodes.push({ id: `server:${t.server}`, type: 'server' as const, server: t.server });
    nodes.push({ id: `tool:${t.server}.${t.tool}`, type: 'tool' as const, server: t.server, tool: t.tool, calls: t.calls });
    edges.push({ from: `agent:${t.agent}`, to: `server:${t.server}`, type: 'connects' as const });
    edges.push({ from: `server:${t.server}`, to: `tool:${t.server}.${t.tool}`, type: 'exposes' as const });
    if (t.capability) {
      edges.push({ from: `tool:${t.server}.${t.tool}`, to: `capability:${t.capability}`, type: 'has_capability' as const });
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

describe('diffGraphs', () => {
  it('finds over-privileged and shadow tools', () => {
    const potential = graph('static', [
      { agent: 'a', server: 's', tool: 'read_file', capability: 'read-secret' },
      { agent: 'a', server: 's', tool: 'send_email', capability: 'external-communication' },
    ]);
    const observed = graph('observed', [
      { agent: 'a', server: 's', tool: 'read_file', capability: 'read-secret', calls: 12 },
      { agent: 'a', server: 's', tool: 'shadow_tool', capability: 'exec', calls: 3 },
    ]);
    const diff = diffGraphs(potential, observed);
    expect(diff.overPrivileged.map((e) => e.tool)).toEqual(['send_email']);
    expect(diff.shadow.map((e) => e.tool)).toEqual(['shadow_tool']);
    expect(diff.summary).toMatchObject({ potentialTools: 2, observedTools: 2, overPrivileged: 1, shadow: 1 });
  });

  it('normalizes server prefixes and merges agents', () => {
    const potential = graph('static', [
      { agent: 'cursor', server: 'mcp-server-filesystem', tool: 'read_file', capability: 'read-secret' },
      { agent: 'dsh', server: 'pod-filesystem', tool: 'read_file', capability: 'read-secret' },
    ]);
    const observed = graph('observed', [
      { agent: 'codex', server: 'filesystem', tool: 'read_file', capability: 'read-secret', calls: 5 },
    ]);
    const diff = diffGraphs(potential, observed);
    expect(diff.overPrivileged).toHaveLength(0);
    expect(diff.shadow).toHaveLength(0);
  });
});
