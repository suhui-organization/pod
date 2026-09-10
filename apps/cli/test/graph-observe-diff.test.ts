import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AuditLog, writeAuditFile, type NewAuditEntry } from '@podsec/audit';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '../src/index.ts');
const DANGER = join(HERE, 'fixtures/graph/danger-server.ts');

function entry(tool: string, extra: Partial<NewAuditEntry> = {}): NewAuditEntry {
  return {
    agent: 'claude-code',
    session: 's',
    server: 'demo',
    tool,
    argsHash: 'h',
    decision: 'allow',
    outcome: 'ok',
    policyVersion: '0.1.0',
    ...extra,
  };
}

function setup(): { home: string; auditDir: string; outDir: string } {
  const home = mkdtempSync(join(tmpdir(), 'pod-observe-'));
  writeFileSync(
    join(home, '.claude.json'),
    JSON.stringify({ mcpServers: { demo: { command: process.execPath, args: ['--import', 'tsx', DANGER] } } }),
    'utf8',
  );
  const auditDir = join(home, 'audit');
  const log = new AuditLog('0.1.0');
  log.append(entry('read_file', { reason: 'argument hits sensitive path pattern ".env" (secrets-input)' }));
  log.append(entry('read_file'));
  log.append(entry('send_email'));
  log.append(entry('shadow_tool'));
  writeAuditFile(join(auditDir, 'claude-code', 'demo.jsonl'), log);
  const outDir = join(home, '.pod', 'graph');
  const build = spawnSync(process.execPath, ['--import', 'tsx', CLI, 'graph', 'build', '--home', home], {
    encoding: 'utf8',
    timeout: 30_000,
  });
  expect(build.status).toBe(0);
  return { home, auditDir, outDir };
}

describe('pod graph observe/diff/mark', () => {
  it('builds an observed graph and diffs it against potential', () => {
    const { auditDir, outDir } = setup();
    const observe = spawnSync(
      process.execPath,
      [
        '--import', 'tsx', CLI, 'graph', 'observe',
        '--audit-dir', auditDir,
        '--out-dir', outDir,
        '--graph', join(outDir, 'potential.json'),
        '--out', join(outDir, 'observed.json'),
      ],
      { encoding: 'utf8', timeout: 30_000 },
    );
    expect(observe.status).toBe(0);
    const observed = JSON.parse(readFileSync(join(outDir, 'observed.json'), 'utf8'));
    expect(observed.source).toBe('observed');
    expect(observed.nodes.some((n: { id: string }) => n.id === 'tool:demo.read_file')).toBe(true);
    expect(observed.nodes.some((n: { id: string }) => n.id === 'tool:demo.shadow_tool')).toBe(true);

    const diffRes = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'graph', 'diff', '--graph', join(outDir, 'potential.json'), '--observed', join(outDir, 'observed.json'), '--out-dir', outDir],
      { encoding: 'utf8', timeout: 30_000 },
    );
    expect(diffRes.status).toBe(0);
    const diff = JSON.parse(readFileSync(join(outDir, 'diff.json'), 'utf8'));
    expect(diff.overPrivileged.some((e: { tool: string }) => e.tool === 'execute_command')).toBe(true);
    expect(diff.shadow.some((e: { tool: string }) => e.tool === 'shadow_tool')).toBe(true);
    expect(existsSync(join(outDir, 'diff.md'))).toBe(true);
  });

  it('records feedback with pod graph mark', () => {
    const { outDir } = setup();
    const mark = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'graph', 'mark', 'chain-001', 'confirmed', '--note', 'real risk', '--out-dir', outDir],
      { encoding: 'utf8', timeout: 30_000 },
    );
    expect(mark.status).toBe(0);
    const feedback = JSON.parse(readFileSync(join(outDir, 'feedback.json'), 'utf8'));
    expect(feedback.entries[0]).toMatchObject({ id: 'chain-001', verdict: 'confirmed', note: 'real risk' });
  });
});
