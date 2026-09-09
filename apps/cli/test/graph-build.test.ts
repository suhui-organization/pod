import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '../src/index.ts');
const DANGER = join(HERE, 'fixtures/graph/danger-server.ts');

function fixtureHome(): string {
  const home = mkdtempSync(join(tmpdir(), 'pod-graph-build-'));
  writeFileSync(
    join(home, '.claude.json'),
    JSON.stringify({ mcpServers: { demo: { command: process.execPath, args: ['--import', 'tsx', DANGER] } } }),
    'utf8',
  );
  return home;
}

describe('pod graph build', () => {
  it('writes a potential graph and prints a summary', () => {
    const home = fixtureHome();
    const out = join(home, '.pod', 'graph', 'potential.json');
    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'graph', 'build', '--home', home, '--out', out],
      { encoding: 'utf8', timeout: 30_000 },
    );
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('pod graph');
    const graph = JSON.parse(readFileSync(out, 'utf8'));
    expect(graph.source).toBe('static');
    expect(graph.nodes.some((n: { id: string }) => n.id === 'tool:demo.read_file')).toBe(true);
  });
});
