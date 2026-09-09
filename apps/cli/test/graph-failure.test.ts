import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { GRAPH_SCHEMA_VERSION } from '@podsec/graph';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '../src/index.ts');
const HANGING = join(HERE, 'fixtures/graph/hanging-server.ts');

function run(args: string[]): ReturnType<typeof spawnSync> {
  return spawnSync(process.execPath, ['--import', 'tsx', CLI, ...args], { encoding: 'utf8', timeout: 30_000 });
}

describe('graph failure modes', () => {
  it('warns config_unreadable and exits 0', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-graph-bad-config-'));
    writeFileSync(join(home, '.claude.json'), '{bad', 'utf8');
    const res = run(['graph', 'build', '--home', home, '--json']);
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('config_unreadable');
  });

  it('warns server_unintrospectable on timeout and exits 0', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-graph-timeout-'));
    writeFileSync(
      join(home, '.claude.json'),
      JSON.stringify({ mcpServers: { demo: { command: process.execPath, args: ['--import', 'tsx', HANGING] } } }),
      'utf8',
    );
    const res = run(['graph', 'build', '--home', home, '--timeout', '500', '--json']);
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('server_unintrospectable');
  });

  it('exits 2 on an unsupported graph schema version', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-graph-bad-schema-'));
    writeFileSync(
      join(dir, 'potential.json'),
      JSON.stringify({
        schema_version: '9.9.9',
        source: 'static',
        generated_at: '2026-09-09T00:00:00.000Z',
        meta: { tool_version: '0.1.0', config_fingerprint: 'x', warnings: [] },
        nodes: [],
        edges: [],
      }),
      'utf8',
    );
    const res = run(['graph', 'toxic', '--graph', join(dir, 'potential.json'), '--out-dir', dir]);
    expect(res.status).toBe(2);
    expect(res.stderr).toContain('unsupported graph schema_version');
  });

  it('warns stale_graph when generated_at is old', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-graph-stale-'));
    writeFileSync(
      join(dir, 'potential.json'),
      JSON.stringify({
        schema_version: GRAPH_SCHEMA_VERSION,
        source: 'static',
        generated_at: '2020-01-01T00:00:00.000Z',
        meta: { tool_version: '0.1.0', config_fingerprint: 'x', warnings: [] },
        nodes: [],
        edges: [],
      }),
      'utf8',
    );
    const res = run(['graph', 'toxic', '--graph', join(dir, 'potential.json'), '--out-dir', dir, '--json']);
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('stale_graph');
  });
});
