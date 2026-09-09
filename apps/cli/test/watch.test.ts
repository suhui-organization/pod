/**
 * pod watch / notify 测试：审批队列提示、交互裁决、桌面通知注入。
 */
import { describe, it, expect, vi } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { notifyApproval } from '../src/notify.js';
import { watchPending } from '../src/watch.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_INDEX = join(HERE, '../src/index.ts');

describe('notifyApproval', () => {
  it('uses osascript on macOS', () => {
    const run = vi.fn();
    notifyApproval({ id: 'fs-1', server: 'filesystem', tool: 'write_file' }, { platform: 'darwin', run });
    expect(run).toHaveBeenCalledTimes(1);
    const [cmd, args] = run.mock.calls[0]!;
    expect(cmd).toBe('osascript');
    expect(args.join(' ')).toContain('filesystem.write_file');
  });

  it('is a no-op on unsupported platforms and swallows runner errors', () => {
    const run = vi.fn();
    notifyApproval({ id: 'x', server: 's', tool: 't' }, { platform: 'win32', run });
    expect(run).not.toHaveBeenCalled();
    expect(() =>
      notifyApproval({ id: 'x', server: 's', tool: 't' }, { platform: 'darwin', run: () => { throw new Error('boom'); } }),
    ).not.toThrow();
  });
});

describe('watchPending', () => {
  it('prints actionable commands in non-interactive mode', async () => {
    const lines: string[] = [];
    await watchPending({
      pendingDir: '/tmp/pod-watch',
      intervalMs: 1,
      once: true,
      approver: 'tester',
      interactive: false,
      log: (m) => lines.push(m),
      list: () => [{ id: 'fs-1', server: 'filesystem', tool: 'write_file' }],
    });
    expect(lines.join('\n')).toContain('APPROVAL #fs-1');
    expect(lines.join('\n')).toContain('pod approve --id fs-1');
    expect(lines.join('\n')).toContain('pod deny --id fs-1');
  });

  it('approves interactively through the injected prompt/decide', async () => {
    const lines: string[] = [];
    const decisions: Array<{ id: string; approved: boolean }> = [];
    await watchPending({
      pendingDir: '/tmp/pod-watch',
      intervalMs: 1,
      once: true,
      approver: 'walden',
      interactive: true,
      log: (m) => lines.push(m),
      list: () => [{ id: 'fs-2', server: 'filesystem', tool: 'edit_file' }],
      prompt: async () => 'approve',
      decide: (_dir, id, d) => decisions.push({ id, approved: d.approved }),
    });
    expect(decisions).toEqual([{ id: 'fs-2', approved: true }]);
    expect(lines.join('\n')).toContain('approved fs-2 by walden');
  });

  it('does not re-prompt for an id already seen', async () => {
    let promptCalls = 0;
    let iterations = 0;
    await watchPending({
      pendingDir: '/tmp/pod-watch',
      intervalMs: 1,
      once: false,
      approver: 'walden',
      interactive: true,
      log: () => {},
      list: () => [{ id: 'fs-3', server: 's', tool: 't' }],
      prompt: async () => {
        promptCalls += 1;
        return 'skip';
      },
      decide: () => {},
      sleep: async () => {
        iterations += 1;
        if (iterations >= 2) throw new Error('stop');
      },
    }).catch(() => {});
    expect(promptCalls).toBe(1);
  });
});

describe('pod watch (CLI)', () => {
  it('prints pending approvals with --once', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-watch-cli-'));
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, 'demo-1.json'),
      JSON.stringify({ id: 'demo-1', agent: 'a', server: 'demo', tool: 'echo', args: {} }),
      'utf8',
    );
    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI_INDEX, 'watch', '--once', '--pending-dir', dir],
      { encoding: 'utf8' },
    );
    expect(res.status).toBe(0);
    expect(res.stderr).toContain('APPROVAL #demo-1');
    expect(res.stderr).toContain('pod approve --id demo-1');
  });
});
