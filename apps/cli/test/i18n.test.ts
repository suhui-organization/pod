/**
 * CLI 中英切换的端到端测试：真跑子进程，断言用户能看到的输出。
 * 语言来源有两条：`--lang` 与 `POD_LANG`（都走 @podsec/i18n 的同一套解析）。
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_INDEX = join(HERE, '../src/index.ts');

function run(args: string[], env: Record<string, string> = {}): string {
  const res = spawnSync(process.execPath, ['--import', 'tsx', CLI_INDEX, ...args], {
    encoding: 'utf8',
    env: { ...process.env, HOME: mkdtempSync(join(tmpdir(), 'pod-i18n-')), ...env },
  });
  // CLI 日志走 stderr（stdio 被 MCP 占用），断言看合并输出
  return `${res.stdout}${res.stderr}`;
}

describe('pod --lang', () => {
  it('--help --lang en-US 是英文，默认是中文', () => {
    const en = run(['--help', '--lang', 'en-US']);
    expect(en).toContain('least-privilege compiler for AI agents');
    expect(en).toContain('Usage:');
    expect(en).not.toContain('只录不拦模式');

    const zh = run(['--help']);
    expect(zh).toContain('只录不拦模式');
  });

  it('POD_LANG 环境变量生效', () => {
    const out = run(['--help'], { POD_LANG: 'en-US' });
    expect(out).toContain('least-privilege compiler for AI agents');
  });

  it('不支持的语言明确报错（不静默回落）', () => {
    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI_INDEX, '--help', '--lang', 'fr-FR'],
      { encoding: 'utf8' },
    );
    expect(res.status).toBe(1);
    expect(`${res.stdout}${res.stderr}`).toContain('supported: zh-CN, en-US');
  });

  it('命令输出随语言切换（init / export-evidence）', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-i18n-cmd-'));
    const init = run(['init', '--template', 'baseline', '--lang', 'en-US'], { HOME: home });
    expect(init).toContain('the rules are yours');
    expect(init).not.toContain('判定规则归你');

    run(['ingest', '--agent', 'a', '--server', 's', '--tool', 't'], { HOME: home });
    const ev = run(['export-evidence', '--lang', 'en-US'], { HOME: home });
    expect(ev).toContain('Evidence bundle exported');
    expect(ev).toContain('Audit files: 1');
  });
});
