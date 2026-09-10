import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '../src/index.ts');
const DANGER = join(HERE, 'fixtures/graph/danger-server.ts');

describe('pod graph explain', () => {
  it('prints a known path id', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-graph-explain-'));
    writeFileSync(
      join(home, '.claude.json'),
      JSON.stringify({ mcpServers: { demo: { command: process.execPath, args: ['--import', 'tsx', DANGER] } } }),
      'utf8',
    );
    const outDir = join(home, '.pod', 'graph');
    spawnSync(process.execPath, ['--import', 'tsx', CLI, 'graph', 'build', '--home', home], { timeout: 30_000 });
    spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'graph', 'toxic', '--out-dir', outDir, '--min-confidence', '0.4'],
      { timeout: 30_000 },
    );
    const paths = JSON.parse(readFileSync(join(outDir, 'paths.json'), 'utf8')) as Array<{ id: string }>;
    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'graph', 'explain', paths[0]!.id, '--out-dir', outDir],
      { encoding: 'utf8', timeout: 30_000 },
    );
    expect(res.status).toBe(0);
    expect(res.stdout).toContain(paths[0]!.id);
    expect(res.stdout).toContain('source:');
    expect(res.stdout).toContain('sink:');
  });

  it('prints a chain id with its chain diff', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-graph-explain-chain-'));
    writeFileSync(
      join(home, '.claude.json'),
      JSON.stringify({ mcpServers: { demo: { command: process.execPath, args: ['--import', 'tsx', DANGER] } } }),
      'utf8',
    );
    const outDir = join(home, '.pod', 'graph');
    const baseline = join(home, 'baseline.json');
    writeFileSync(
      baseline,
      JSON.stringify({
        version: '0.1.0',
        agent: 'claude-code',
        defaultDecision: 'deny',
        servers: { demo: { allow: ['read_file', 'send_email', 'execute_command', 'http_request', 'delete_file'] } },
      }),
      'utf8',
    );
    spawnSync(process.execPath, ['--import', 'tsx', CLI, 'graph', 'build', '--home', home], { timeout: 30_000 });
    spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'graph', 'toxic', '--out-dir', outDir, '--diff', baseline, '--min-confidence', '0.4'],
      { timeout: 30_000 },
    );
    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'graph', 'explain', 'chain-001', '--out-dir', outDir],
      { encoding: 'utf8', timeout: 30_000 },
    );
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('chain-001');
    expect(res.stdout).toContain('断链');
  });
});
