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

  it('报表类输出随语言切换（scan / posture）', () => {
    const scan = run(['scan', '--lang', 'en-US']);
    expect(scan).toContain('# pod scan report');
    expect(scan).toContain('## 1. Agent inventory');
    expect(scan).not.toContain('信任基线');

    const posture = run(['posture', '--lang', 'en-US']);
    expect(posture).toContain('# pod posture — control-plane posture');
    expect(posture).toContain('## Facts collected');
  });

  it('控制平面明细行随语言切换（identity / delegate）', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-i18n-cp-'));
    const init = run(['identity', 'init', '--agent', 'demo', '--lang', 'en-US'], { HOME: home });
    expect(init).toContain('Identity created: demo');
    expect(init).toContain('never share it');

    run(['identity', 'init', '--agent', 'worker'], { HOME: home });
    const deleg = run(
      [
        'delegate', 'issue', '--parent', 'demo', '--child', 'worker',
        '--capability', 'read-private-data', '--ttl', '600', '--lang', 'en-US',
      ],
      { HOME: home },
    );
    expect(deleg).toContain('Delegation issued: demo → worker');
    expect(deleg).toContain('Capabilities: read-private-data');
  });

  it('控制平面与报表的剩余输出不留中文（coverage / timeline / doctor / trace）', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-i18n-rest-'));
    for (const args of [
      ['coverage'],
      ['timeline'],
      ['doctor'],
      ['trace', 'demo'],
      ['anomaly'],
      ['quarantine', 'list'],
    ]) {
      const out = run([...args, '--lang', 'en-US'], { HOME: home });
      const cn = out.split('\n').filter((l) => /[\u4e00-\u9fa5]/.test(l));
      // 这里只拦"整句仍是中文"：本用例跑在空 HOME 下，不会有中文的机器名/路径混进来
      expect(cn, `${args.join(' ')} 仍有中文：${cn.join(' | ')}`).toEqual([]);
    }
  });
});
