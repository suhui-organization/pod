import { describe, expect, it } from 'vitest';
import { GRAPH_SCHEMA_VERSION, parseGraph, serializeGraph } from './index.js';

const graph = {
  schema_version: GRAPH_SCHEMA_VERSION,
  source: 'static' as const,
  generated_at: '2026-09-09T00:00:00.000Z',
  meta: { tool_version: '0.1.0', config_fingerprint: 'sha256:x', warnings: [] },
  nodes: [
    { id: 'tool:b.z', type: 'tool' as const },
    { id: 'agent:a', type: 'agent' as const },
  ],
  edges: [
    { from: 'server:s', to: 'tool:b.z', type: 'exposes' as const },
    { from: 'agent:a', to: 'server:s', type: 'connects' as const },
  ],
};

describe('serializeGraph', () => {
  it('sorts nodes and edges for stable git diffs', () => {
    const text = serializeGraph(graph);
    expect(text.indexOf('agent:a')).toBeLessThan(text.indexOf('tool:b.z'));
    expect(text.endsWith('\n')).toBe(true);
  });
});

describe('parseGraph', () => {
  it('round-trips a valid graph', () => {
    expect(parseGraph(serializeGraph(graph)).schema_version).toBe(GRAPH_SCHEMA_VERSION);
  });

  it('rejects a schema version mismatch', () => {
    expect(() => parseGraph(JSON.stringify({ ...graph, schema_version: '9.9.9' }))).toThrow(
      /unsupported graph schema_version/,
    );
  });

  it('rejects invalid JSON', () => {
    expect(() => parseGraph('{nope')).toThrow(/not valid JSON/);
  });
});
