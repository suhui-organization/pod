import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '../src/index.ts');
const DANGER = join(HERE, 'fixtures/graph/danger-server.ts');

function builtHome(): string {
  const home = mkdtempSync(join(tmpdir(), 'pod-graph-toxic-'));
  writeFileSync(
    join(home, '.claude.json'),
    JSON.stringify({ mcpServers: { demo: { command: process.execPath, args: ['--import', 'tsx', DANGER] } } }),
    'utf8',
  );
  const res = spawnSync(process.execPath, ['--import', 'tsx', CLI, 'graph', 'build', '--home', home], {
    encoding: 'utf8',
    timeout: 30_000,
  });
  expect(res.status).toBe(0);
  return home;
}

describe('pod graph toxic', () => {
  it('writes paths/report/policy-diff and exits 1 on high severity', () => {
    const home = builtHome();
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
    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'graph', 'toxic', '--out-dir', outDir, '--diff', baseline, '--min-confidence', '0.4'],
      { encoding: 'utf8', timeout: 30_000 },
    );
    expect(res.status).toBe(1);
    expect(res.stdout).toContain('path-001');
    expect(existsSync(join(outDir, 'paths.json'))).toBe(true);
    expect(existsSync(join(outDir, 'report.md'))).toBe(true);
    expect(existsSync(join(outDir, 'chains.json'))).toBe(true);
    const diff = JSON.parse(readFileSync(join(outDir, 'policy-diff.json'), 'utf8'));
    expect(diff.length).toBeGreaterThan(0);
    const chains = JSON.parse(readFileSync(join(outDir, 'chains.json'), 'utf8'));
    expect(chains[0].chain_diff).toBeTruthy();
  });
});
