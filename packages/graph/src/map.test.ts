import { describe, expect, it } from 'vitest';
import { capabilityMapFromGraph } from './map.js';
import type { CapabilityGraph } from './types.js';

const graph: CapabilityGraph = {
  schema_version: '0.1.0',
  source: 'static',
  generated_at: '2026-09-09T00:00:00.000Z',
  meta: { tool_version: '0.1.0', config_fingerprint: 'sha256:x', warnings: [] },
  nodes: [
    { id: 'tool:s.send_email', type: 'tool', server: 's', tool: 'send_email' },
    { id: 'tool:s.read_file', type: 'tool', server: 's', tool: 'read_file' },
  ],
  edges: [
    { from: 'tool:s.send_email', to: 'capability:external-communication', type: 'has_capability' },
    { from: 'tool:s.send_email', to: 'capability:exec', type: 'has_capability' },
    { from: 'tool:s.read_file', to: 'capability:read-secret', type: 'has_capability' },
  ],
};

describe('capabilityMapFromGraph', () => {
  it('maps server.tool to unique capabilities', () => {
    expect(capabilityMapFromGraph(graph)).toEqual({
      's.send_email': ['external-communication', 'exec'],
      's.read_file': ['read-secret'],
    });
  });
});
