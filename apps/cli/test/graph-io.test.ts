import { describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GRAPH_SCHEMA_VERSION, type CapabilityGraph } from '@podsec/graph';
import { readGraphFile, writeGraph } from '../src/graph/io.js';
import { cacheKey, readSchemaCache, writeSchemaCache } from '../src/graph/schema-cache.js';

const graph: CapabilityGraph = {
  schema_version: GRAPH_SCHEMA_VERSION,
  source: 'static',
  generated_at: '2026-09-09T00:00:00.000Z',
  meta: { tool_version: '0.1.0', config_fingerprint: 'sha256:x', warnings: [] },
  nodes: [],
  edges: [],
};

describe('graph io', () => {
  it('writes atomically and reads back', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-graph-io-'));
    const path = join(dir, 'potential.json');
    writeGraph(path, graph);
    expect(readGraphFile(path)).toEqual(graph);
  });

  it('rejects a corrupt graph file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-graph-io-bad-'));
    const path = join(dir, 'potential.json');
    writeFileSync(path, '{bad', 'utf8');
    expect(() => readGraphFile(path)).toThrow(/not valid JSON/);
  });
});

describe('schema cache', () => {
  it('round-trips tool descriptors', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-graph-cache-'));
    const key = cacheKey('node', ['server.js']);
    expect(readSchemaCache(dir, key)).toBeNull();
    writeSchemaCache(dir, key, [{ name: 'read_file' }]);
    expect(readSchemaCache(dir, key)).toEqual([{ name: 'read_file' }]);
    expect(readFileSync(join(dir, `${key}.json`), 'utf8')).toContain('read_file');
  });
});
