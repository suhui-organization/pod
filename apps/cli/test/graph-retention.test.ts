import { describe, expect, it } from 'vitest';
import { appendFileSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  activeDays,
  addDays,
  artifactDays,
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
