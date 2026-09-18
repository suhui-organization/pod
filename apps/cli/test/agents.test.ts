// pod agents 端到端测试：扫描 → 纳管 → 再扫 → 移除。
//
// 这条命令与控制台（pod ui 的「加入监控」按钮）走的是同一条写路径
// （@podsec/console 的 enrollAgent），所以这里也顺带守住了"控制台能做的，
// CLI 也能做"这条产品纪律。
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeEach, describe, expect, it } from 'vitest';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_SRC = join(HERE, '../src/index.ts');

let home: string;

function run(args: string[]): { out: string; stdout: string; status: number | null } {
  const res = spawnSync(process.execPath, ['--import', 'tsx', CLI_SRC, ...args], {
    encoding: 'utf8',
    env: { ...process.env, HOME: home },
  });
  return {
    out: `${res.stdout ?? ''}${res.stderr ?? ''}`,
    stdout: res.stdout ?? '',
    status: res.status,
  };
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'pod-agents-'));
  mkdirSync(join(home, '.claude'), { recursive: true });
  writeFileSync(
    join(home, '.claude.json'),
    JSON.stringify({ mcpServers: { github: { command: 'npx', args: ['-y', 'pkg'] } } }),
    'utf8',
  );
});

describe('pod agents scan', () => {
  it('列出已安装的 harness 与纳管状态', () => {
    const { out, status } = run(['agents', 'scan']);
    expect(status).toBe(0);
    expect(out).toContain('本机已安装');
    expect(out).toContain('claude-code');
    expect(out).toContain('未纳管：claude-code');
  });

  it('--json 给出机器可读的列表', () => {
    const { stdout } = run(['agents', 'scan', '--json']);
    const rows = JSON.parse(stdout) as Array<{ id: string; installed: boolean; managed: boolean }>;
    const claude = rows.find((r) => r.id === 'claude-code')!;
    expect(claude.installed).toBe(true);
    expect(claude.managed).toBe(false);
  });
});

describe('pod agents enroll / forget', () => {
  it('纳管建身份 + 零权限策略 + 审计目录，并打印下一步', () => {
    const { out, status } = run(['agents', 'enroll', '--harness', 'claude-code']);
    expect(status).toBe(0);
    expect(out).toContain('已纳管 agent claude-code');
    expect(out).toContain('pod onboard --yes');
    expect(out).toContain('不改动 harness 的配置');

    expect(existsSync(join(home, '.pod/identity/claude-code/private.pem'))).toBe(true);
    expect(existsSync(join(home, '.pod/policies/claude-code.json'))).toBe(true);
    const policy = JSON.parse(readFileSync(join(home, '.pod/policies/claude-code.json'), 'utf8')) as {
      defaultDecision: string;
      servers: Record<string, unknown>;
    };
    expect(policy.defaultDecision).toBe('deny');
    expect(Object.keys(policy.servers)).toHaveLength(0);
  });

  it('重复纳管是幂等的（第二次无改动）', () => {
    run(['agents', 'enroll', '--harness', 'claude-code']);
    const second = run(['agents', 'enroll', '--harness', 'claude-code']);
    expect(second.out).toContain('已在纳管中');
  });

  it('纳管后 scan 显示已纳管', () => {
    run(['agents', 'enroll', '--harness', 'claude-code']);
    const { out } = run(['agents', 'scan']);
    expect(out).toContain('1 个已纳管');
    expect(out).not.toContain('未纳管：claude-code');
  });

  it('--agent 可以自定义 agent 名', () => {
    const { out } = run(['agents', 'enroll', '--harness', 'claude-code', '--agent', 'work-claude']);
    expect(out).toContain('已纳管 agent work-claude');
    expect(existsSync(join(home, '.pod/policies/work-claude.json'))).toBe(true);
  });

  it('非法 agent 名被拒，且不留产物', () => {
    const { out, status } = run(['agents', 'enroll', '--harness', 'claude-code', '--agent', '../evil']);
    expect(status).toBe(1);
    expect(out).toContain('非法 agent 名');
    expect(existsSync(join(home, '.pod/policies'))).toBe(false);
  });

  it('forget 删策略、留身份，并在审计链里留痕', () => {
    run(['agents', 'enroll', '--harness', 'claude-code']);
    const { out, status } = run(['agents', 'forget', '--agent', 'claude-code']);
    expect(status).toBe(0);
    expect(out).toContain('已移除纳管 claude-code');
    expect(existsSync(join(home, '.pod/policies/claude-code.json'))).toBe(false);
    expect(existsSync(join(home, '.pod/identity/claude-code/private.pem'))).toBe(true);
    const chain = readFileSync(join(home, '.pod/audit/claude-code/control.jsonl'), 'utf8');
    expect(chain).toContain('console:enroll:claude-code');
    expect(chain).toContain('console:forget:claude-code');
  });

  it('forget --purge-identity 才删身份', () => {
    run(['agents', 'enroll', '--harness', 'claude-code']);
    run(['agents', 'forget', '--agent', 'claude-code', '--purge-identity']);
    expect(existsSync(join(home, '.pod/identity/claude-code'))).toBe(false);
  });

  it('未知子命令给出可用列表', () => {
    const { out, status } = run(['agents', 'nope']);
    expect(status).toBe(1);
    expect(out).toContain('scan / enroll / onboard / enforce / revert / forget');
  });
});

describe('pod agents onboard / revert（接管）', () => {
  /** 造一个假的 pod 可执行文件，让"pod 在不在 PATH"的前置检查通过 */
  function withFakePodBin(): string {
    const bin = join(home, 'fake-pod');
    writeFileSync(bin, '#!/bin/sh\nexit 0\n', 'utf8');
    chmodSync(bin, 0o755);
    return bin;
  }

  it('默认只打印计划，不改配置（要 --yes 才动）', () => {
    const before = readFileSync(join(home, '.claude.json'), 'utf8');
    const { out, status } = run(['agents', 'onboard', '--harness', 'claude-code', '--pod-bin', withFakePodBin()]);
    expect(status).toBe(0);
    expect(out).toContain('接管计划（dry-run');
    expect(out).toContain('改'); // 改前/改后两行
    expect(out).toContain('serve --record-only');
    expect(out).toContain('备份：');
    expect(readFileSync(join(home, '.claude.json'), 'utf8')).toBe(before);
  });

  it('--yes 接管：改写配置 + 备份 + 写策略 + 入链', () => {
    const { out, status } = run(['agents', 'onboard', '--harness', 'claude-code', '--pod-bin', withFakePodBin(), '--yes']);
    expect(status).toBe(0);
    expect(out).toContain('已接管 claude-code');
    const config = JSON.parse(readFileSync(join(home, '.claude.json'), 'utf8')) as {
      mcpServers: Record<string, { command: string; args: string[] }>;
    };
    expect(config.mcpServers.github!.args).toContain('--record-only');
    expect(existsSync(join(home, '.pod/policies/onboard-claude-code.json'))).toBe(true);
    const chain = readFileSync(join(home, '.pod/audit/claude-code/control.jsonl'), 'utf8');
    expect(chain).toContain('console:takeover:claude-code');
  });

  it('revert 从备份还原', () => {
    const before = readFileSync(join(home, '.claude.json'), 'utf8');
    run(['agents', 'onboard', '--harness', 'claude-code', '--pod-bin', withFakePodBin(), '--yes']);
    const { out, status } = run(['agents', 'revert', '--agent', 'claude-code']);
    expect(status).toBe(0);
    expect(out).toContain('已还原 1 个配置');
    expect(readFileSync(join(home, '.claude.json'), 'utf8')).toBe(before);
  });

  it('pod 不在 PATH 时拒绝接管（避免写出跑不起来的配置）', () => {
    const before = readFileSync(join(home, '.claude.json'), 'utf8');
    const { out, status } = run([
      'agents', 'onboard', '--harness', 'claude-code', '--pod-bin', join(home, 'missing-pod'), '--yes',
    ]);
    expect(status).toBe(1);
    expect(out).toContain('接管失败');
    expect(readFileSync(join(home, '.claude.json'), 'utf8')).toBe(before);
  });
});

describe('pod agents enforce（切执法 / 回到只录不拦）', () => {
  function withFakePodBin(): string {
    const bin = join(home, 'fake-pod');
    writeFileSync(bin, '#!/bin/sh\nexit 0\n', 'utf8');
    chmodSync(bin, 0o755);
    return bin;
  }

  function writePolicy(): string {
    mkdirSync(join(home, '.pod/policies'), { recursive: true });
    const path = join(home, '.pod/policies/draft.json');
    writeFileSync(
      path,
      JSON.stringify({
        version: '0.1.0',
        agent: 'claude-code',
        defaultDecision: 'deny',
        servers: { github: { allow: ['search'], approve: ['create_issue'] } },
      }),
      'utf8',
    );
    return path;
  }

  it('没有编译好的策略时拒绝切执法（并给出要跑的命令）', () => {
    run(['agents', 'enroll', '--harness', 'claude-code']);
    run(['agents', 'onboard', '--harness', 'claude-code', '--pod-bin', withFakePodBin(), '--yes']);
    const { out, status } = run(['agents', 'enforce', '--harness', 'claude-code', '--yes']);
    expect(status).toBe(1);
    expect(out).toContain('切执法失败');
    expect(out).toContain('pod policy draft');
  });

  it('dry-run 打印改前/改后与策略概要，不改配置', () => {
    run(['agents', 'enroll', '--harness', 'claude-code']);
    run(['agents', 'onboard', '--harness', 'claude-code', '--pod-bin', withFakePodBin(), '--yes']);
    writePolicy();
    const before = readFileSync(join(home, '.claude.json'), 'utf8');
    const { out, status } = run(['agents', 'enforce', '--harness', 'claude-code']);
    expect(status).toBe(0);
    expect(out).toContain('执法计划（dry-run');
    expect(out).toContain('--record-only');
    expect(out).toContain('执法策略：');
    expect(out).toContain('allow 1 / approve 1 / deny 0');
    expect(readFileSync(join(home, '.claude.json'), 'utf8')).toBe(before);
  });

  it('--yes 切执法：去掉 --record-only 并指向编译好的策略', () => {
    run(['agents', 'enroll', '--harness', 'claude-code']);
    run(['agents', 'onboard', '--harness', 'claude-code', '--pod-bin', withFakePodBin(), '--yes']);
    const policy = writePolicy();
    const { out, status } = run(['agents', 'enforce', '--harness', 'claude-code', '--yes']);
    expect(status).toBe(0);
    expect(out).toContain('已切执法 claude-code');
    const config = JSON.parse(readFileSync(join(home, '.claude.json'), 'utf8')) as {
      mcpServers: Record<string, { args: string[] }>;
    };
    const args = config.mcpServers.github!.args;
    expect(args).not.toContain('--record-only');
    expect(args[args.indexOf('--policy') + 1]).toBe(policy);
    expect(readFileSync(join(home, '.pod/audit/claude-code/control.jsonl'), 'utf8')).toContain(
      'console:enforce:claude-code',
    );
  });

  it('--record-only 退回只录不拦', () => {
    run(['agents', 'enroll', '--harness', 'claude-code']);
    run(['agents', 'onboard', '--harness', 'claude-code', '--pod-bin', withFakePodBin(), '--yes']);
    writePolicy();
    run(['agents', 'enforce', '--harness', 'claude-code', '--yes']);
    const { out, status } = run(['agents', 'enforce', '--harness', 'claude-code', '--record-only', '--yes']);
    expect(status).toBe(0);
    expect(out).toContain('已回到只录不拦');
    const config = JSON.parse(readFileSync(join(home, '.claude.json'), 'utf8')) as {
      mcpServers: Record<string, { args: string[] }>;
    };
    expect(config.mcpServers.github!.args).toContain('--record-only');
  });
});
