import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '../src/index.ts');
const WIDE = join(HERE, 'fixtures/graph/wide-server.ts');

function setup(): { home: string; outDir: string; baseline: string } {
  const home = mkdtempSync(join(tmpdir(), 'pod-capability-diff-'));
  writeFileSync(
    join(home, '.claude.json'),
    JSON.stringify({ mcpServers: { demo: { command: process.execPath, args: ['--import', 'tsx', WIDE] } } }),
    'utf8',
  );
  const baseline = join(home, 'baseline.json');
  writeFileSync(
    baseline,
    JSON.stringify({
      version: '0.1.0',
      agent: 'claude-code',
      defaultDecision: 'deny',
      servers: {
        demo: {
          allow: [
            'read_file',
            'read_secret',
            'get_env',
            'read_config',
            'send_email',
            'post_message',
            'webhook_notify',
            'upload_file',
          ],
        },
      },
    }),
    'utf8',
  );
  const outDir = join(home, '.pod', 'graph');
  const build = spawnSync(process.execPath, ['--import', 'tsx', CLI, 'graph', 'build', '--home', home], {
    encoding: 'utf8',
    timeout: 30_000,
  });
  expect(build.status).toBe(0);
  return { home, outDir, baseline };
}

describe('capability-level chain diff', () => {
  it('writes capability-diff.json when no small tool-level cut exists', () => {
    const { outDir, baseline } = setup();
    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'graph', 'toxic', '--out-dir', outDir, '--diff', baseline, '--min-confidence', '0.4'],
      { encoding: 'utf8', timeout: 30_000 },
    );
    expect(res.status).toBe(1);
    const chains = JSON.parse(readFileSync(join(outDir, 'chains.json'), 'utf8'));
    expect(chains.some((c: { chain_diff?: { strategy: string } }) => c.chain_diff?.strategy === 'capability-level')).toBe(
      true,
    );
    expect(existsSync(join(outDir, 'capability-diff.json'))).toBe(true);
    const patches = JSON.parse(readFileSync(join(outDir, 'capability-diff.json'), 'utf8'));
    expect(
      patches.some((p: { capabilityRules?: { approve?: string[] } }) =>
        p.capabilityRules?.approve?.includes('external-communication'),
      ),
    ).toBe(true);
  });

  it('pod graph apply embeds capabilityMap into the policy', () => {
    const { home, outDir, baseline } = setup();
    const out = join(home, 'policy.with-capabilities.json');
    const res = spawnSync(
      process.execPath,
      [
        '--import',
        'tsx',
        CLI,
        'graph',
        'apply',
        '--graph',
        join(outDir, 'potential.json'),
        '--policy',
        baseline,
        '--out',
        out,
      ],
      { encoding: 'utf8', timeout: 30_000 },
    );
    expect(res.status).toBe(0);
    const policy = JSON.parse(readFileSync(out, 'utf8'));
    expect(policy.capabilityMap['demo.send_email']).toContain('external-communication');
    expect(policy.capabilityMap['demo.read_secret']).toContain('read-secret');
  });
});
