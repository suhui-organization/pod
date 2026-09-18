// `pod --version`：排查"我装的是哪一版"必须是一条能跑的命令。
//
// 为什么值得单独一个测试：`--version` 这个选项名已经被
// `pod rules pack --version <pack-version>` 占用（string 类型），
// 所以 `pod --version` 会被 parseArgs 判成"缺参数"而抛错——真机上就是这样坏的。
// 版本号还必须与发版号一致（scripts/preflight-publish.sh 校验四处一致）。
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_INDEX = join(HERE, '../src/index.ts');

function run(args: string[]): { out: string; status: number | null } {
  const res = spawnSync(process.execPath, ['--import', 'tsx', CLI_INDEX, ...args], { encoding: 'utf8' });
  return { out: `${res.stdout ?? ''}${res.stderr ?? ''}`, status: res.status };
}

describe('pod --version', () => {
  it('三种写法都打印版本，且与 apps/cli/package.json 一致', () => {
    const version = JSON.parse(readFileSync(join(HERE, '../package.json'), 'utf8')).version as string;
    for (const flag of ['--version', '-V', 'version']) {
      const { out, status } = run([flag]);
      expect(status, flag).toBe(0);
      expect(out, flag).toContain(`pod ${version}`);
    }
  });

  it('不影响 `pod rules pack --version <pack-version>` 的选项', () => {
    const { out } = run(['rules', 'pack']);
    expect(out).toContain('--version <pack-version>');
    expect(out).not.toContain('pod 0.');
  });
});
