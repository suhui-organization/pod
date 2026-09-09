import { describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildStaticGraph } from '../src/graph/static.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const DANGER = join(HERE, 'fixtures/graph/danger-server.ts');

function fixtureHome(): string {
  const home = mkdtempSync(join(tmpdir(), 'pod-graph-static-'));
  mkdirSync(join(home, '.claude'), { recursive: true });
  writeFileSync(
    join(home, '.claude.json'),
    JSON.stringify({
      mcpServers: {
        demo: { command: process.execPath, args: ['--import', 'tsx', DANGER] },
      },
    }),
    'utf8',
  );
  return home;
}

describe('buildStaticGraph', () => {
  it('discovers tools and classifies them', async () => {
    const home = fixtureHome();
    const { graph } = await buildStaticGraph({
      home,
      noExec: false,
      timeoutMs: 10_000,
      cacheDir: join(home, '.pod', 'graph', 'schema-cache'),
      policy: null,
    });
    expect(graph.nodes.filter((n) => n.type === 'agent')).toHaveLength(1);
    expect(graph.nodes.filter((n) => n.type === 'tool')).toHaveLength(5);
    const read = graph.edges.find((e) => e.from === 'tool:demo.read_file' && e.to === 'capability:read-private-data');
    expect(read?.confidence).toBeGreaterThan(0);
  });

  it('falls back to name heuristics with noExec and warns schema_missing', async () => {
    const home = fixtureHome();
    const { graph } = await buildStaticGraph({
      home,
      noExec: true,
      timeoutMs: 1_000,
      cacheDir: join(home, '.pod', 'graph', 'schema-cache'),
      policy: null,
    });
    expect(graph.meta.warnings.some((w) => w.code === 'schema_missing')).toBe(true);
    expect(graph.nodes.filter((n) => n.type === 'tool')).toHaveLength(0);
  });
});
