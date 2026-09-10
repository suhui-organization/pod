import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '../src/index.ts');
import {
  activeDays,
  addDays,
  artifactDays,
  judgeRetention,
  localDay,
  readUsage,
  recordUsage,
  usageLogPath,
  withinWindow,
  type UsageEntry,
} from '../src/graph/retention.js';

/** 用本地正午构造时间戳，保证 localDay 落在指定日期（与运行机器的时区无关）。 */
function localNoon(year: number, month: number, day: number): string {
  return new Date(year, month - 1, day, 12, 0, 0).toISOString();
}

describe('retention 埋点', () => {
  it('只记录白名单子命令，retention 自身与未知子命令不记录', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-retention-'));
    recordUsage(dir, 'build');
    recordUsage(dir, 'mark');
    recordUsage(dir, 'retention');
    recordUsage(dir, 'nope');
    const lines = readFileSync(usageLogPath(dir), 'utf8').trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(lines.map((line) => JSON.parse(line).cmd)).toEqual(['build', 'mark']);
  });

  it('跳过坏行，不因为一行脏数据失效', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-retention-bad-'));
    recordUsage(dir, 'build');
    appendFileSync(usageLogPath(dir), '{"at": "2026-09-1\n', 'utf8');
    expect(readUsage(dir)).toHaveLength(1);
  });

  it('没有 usage.jsonl 时返回空列表', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-retention-empty-'));
    expect(readUsage(dir)).toEqual([]);
  });
});

describe('活跃日口径 B', () => {
  const usage: UsageEntry[] = [
    { at: localNoon(2026, 9, 10), cmd: 'build' },
    { at: localNoon(2026, 9, 10), cmd: 'explain' }, // 查看，不计入
    { at: localNoon(2026, 9, 10), cmd: 'mark' }, // 标注，不计入
    { at: localNoon(2026, 9, 11), cmd: 'toxic' },
    { at: localNoon(2026, 9, 12), cmd: 'mark' },
  ];

  it('只把分析类命令落成活跃日，同一天多次只算一天', () => {
    expect([...activeDays(usage)].sort()).toEqual(['2026-09-10', '2026-09-11']);
  });

  it('口径可切换：全部命令都算时 mark 也算活跃', () => {
    const all = activeDays(usage, ['build', 'explain', 'mark', 'toxic']);
    expect([...all].sort()).toEqual(['2026-09-10', '2026-09-11', '2026-09-12']);
  });
});

describe('窗口计算', () => {
  it('按本地自然日加减', () => {
    expect(addDays('2026-09-01', -1)).toBe('2026-08-31');
    expect(addDays('2026-09-10', 14)).toBe('2026-09-24');
  });

  it('裁到最近 N 天（含今天）并升序', () => {
    const days = ['2026-08-28', '2026-08-29', '2026-09-01', '2026-09-09', '2026-09-10', '2026-09-11'];
    expect(withinWindow(days, '2026-09-10', 14)).toEqual([
      '2026-08-28',
      '2026-08-29',
      '2026-09-01',
      '2026-09-09',
      '2026-09-10',
    ]);
  });
});

describe('H4 判定', () => {
  const day = (n: number) => `2026-09-${String(n).padStart(2, '0')}`;
  const run = (activeDays: string[], today = day(10), window = 14) =>
    judgeRetention({ activeDays, today, window });

  it('连续满窗口即达成', () => {
    const activeDays = Array.from({ length: 14 }, (_, i) => addDays(day(10), -i));
    expect(run(activeDays)).toEqual({ streak: 14, status: 'met' });
  });

  it('今天还没用不算断档，从昨天起算', () => {
    expect(run([day(8), day(9)])).toEqual({ streak: 2, status: 'on-track' });
  });

  it('今天和昨天都没用就是中断', () => {
    expect(run([day(5), day(6)])).toEqual({ streak: 0, status: 'broken' });
  });

  it('断一天就清零，从最近一次活跃日重新数', () => {
    // 9/5 之后断了 9/6，9/7-9/9 连续三天
    expect(run([day(1), day(2), day(3), day(4), day(5), day(7), day(8), day(9)])).toEqual({
      streak: 3,
      status: 'on-track',
    });
  });

  it('今天活跃则从今天起算', () => {
    expect(run([day(9), day(10)])).toEqual({ streak: 2, status: 'on-track' });
  });

  it('空窗口是中断', () => {
    expect(run([])).toEqual({ streak: 0, status: 'broken' });
  });
});

describe('产物回填', () => {
  it('从 generated_at 与产物 mtime 还原真实证据日', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-retention-artifacts-'));
    const generated = localNoon(2026, 9, 9);
    writeFileSync(join(dir, 'potential.json'), JSON.stringify({ generated_at: generated }), 'utf8');
    writeFileSync(join(dir, 'report.md'), 'x', 'utf8'); // mtime = 今天
    const days = artifactDays(dir);
    expect(days.has('2026-09-09')).toBe(true);
    expect(days.has(localDay(new Date()))).toBe(true);
  });

  it('空目录不报错', () => {
    expect(artifactDays(mkdtempSync(join(tmpdir(), 'pod-retention-none-'))).size).toBe(0);
  });
});

describe('pod graph retention', () => {
  function localNoonOffset(daysAgo: number): string {
    const date = new Date();
    date.setDate(date.getDate() - daysAgo);
    date.setHours(12, 0, 0, 0);
    return date.toISOString();
  }

  it('埋点走 CLI，retention 自身不留痕，并按口径 B 汇总', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-retention-cli-'));
    const outDir = join(home, '.pod', 'graph');
    mkdirSync(outDir, { recursive: true });
    // 昨天做过分析，今天只有查看/标注 → 口径 B 下今昨天连续，今天不算活跃
    writeFileSync(
      usageLogPath(outDir),
      [
        { at: localNoonOffset(1), cmd: 'build' },
        { at: localNoonOffset(0), cmd: 'mark' },
      ]
        .map((entry) => JSON.stringify(entry))
        .join('\n') + '\n',
      'utf8',
    );

    const mark = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'graph', 'mark', 'chain-002', 'false-positive', '--out-dir', outDir],
      { encoding: 'utf8', timeout: 30_000 },
    );
    expect(mark.status).toBe(0);

    const recorded = readUsage(outDir).map((entry) => entry.cmd);
    expect(recorded).toEqual(['build', 'mark', 'mark']);

    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'graph', 'retention', '--out-dir', outDir, '--json'],
      { encoding: 'utf8', timeout: 30_000 },
    );
    expect(res.status).toBe(0);
    const report = JSON.parse(res.stdout);
    expect(report).toMatchObject({
      streak: 1,
      status: 'on-track',
      window: 14,
      feedback: { confirmed: 0, falsePositive: 1 },
    });
    expect(report.activeDays).toEqual([localDay(new Date(localNoonOffset(1)))]);

    // retention 自己不算使用：次数仍是 3 条
    expect(readUsage(outDir)).toHaveLength(3);
  }, 40_000);
});
