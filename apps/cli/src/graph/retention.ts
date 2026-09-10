import { appendFileSync, existsSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { readFeedback } from './feedback.js';

/**
 * H4 留存信号（设计文档 8. Phase 3：连续 2 周主动使用）。
 *
 * 背景：`~/.pod/graph/` 里的产物都是幂等覆盖写的（potential.json / observed.json / …），
 * 只能告诉你「最后一次使用时间」，测不出「连续多少天在用」。
 * 所以这里另开一条 append-only 的 usage.jsonl，只追加，不覆盖。
 */

/** 写进 usage.jsonl 的子命令。原始记录尽量全，口径留给聚合阶段决定。 */
export const RECORDED_CMDS = ['build', 'observe', 'diff', 'toxic', 'explain', 'apply', 'mark', 'baseline'] as const;

/**
 * 口径 B（2026-09-10 与 walden 确认）：只有「重新做了一次分析」的调用才算主动使用。
 * explain / mark / apply 属于查看与标注，不计入活跃日 —— 但它们在 usage.jsonl 里仍有记录，
 * 想换成口径 A（任意调用）或 C（只有 mark/apply）时不需要补数据。
 */
export const ACTIVE_CMDS = ['build', 'observe', 'diff', 'toxic', 'baseline'] as const;

export interface UsageEntry {
  /** ISO 8601 时间戳 */
  at: string;
  cmd: string;
}

export type RetentionStatus = 'met' | 'on-track' | 'broken';

export interface RetentionInput {
  /** 窗口内（含今天）的活跃日，升序排列，形如 '2026-09-10' */
  activeDays: string[];
  /** 本地今天，形如 '2026-09-10' */
  today: string;
  /** 窗口天数，H4 为 14 */
  window: number;
}

export interface RetentionVerdict {
  /** 截至今天的连续活跃天数 */
  streak: number;
  status: RetentionStatus;
}

export interface RetentionReport extends RetentionVerdict {
  window: number;
  today: string;
  /** 窗口内的活跃日，升序 */
  activeDays: string[];
  /** 窗口内缺的天数 */
  missingDays: number;
  lastActive: string | null;
  feedback: { confirmed: number; falsePositive: number };
}

export function usageLogPath(outDir: string): string {
  return join(outDir, 'usage.jsonl');
}

/**
 * 追加一条使用记录。无法识别的子命令（含 retention 自身）不记录：
 * 监控器自己跑起来不算「主动使用」，否则 streak 会永远为真。
 */
export function recordUsage(outDir: string, cmd: string, at: Date = new Date()): void {
  if (!(RECORDED_CMDS as readonly string[]).includes(cmd)) return;
  const path = usageLogPath(outDir);
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, JSON.stringify({ at: at.toISOString(), cmd } satisfies UsageEntry) + '\n', 'utf8');
}

/** 读取使用记录；坏行（半截写入、手工编辑）直接跳过，不让监控器因为一行脏数据失效。 */
export function readUsage(outDir: string): UsageEntry[] {
  const path = usageLogPath(outDir);
  if (!existsSync(path)) return [];
  const entries: UsageEntry[] = [];
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '') continue;
    try {
      const parsed = JSON.parse(trimmed) as UsageEntry;
      if (typeof parsed?.at === 'string' && typeof parsed?.cmd === 'string') entries.push(parsed);
    } catch {
      // 跳过坏行
    }
  }
  return entries;
}

/** ISO 时间戳 → 本地自然日 'YYYY-MM-DD'。留存的「一天」是本地日历日，不是滚动时钟窗口。 */
export function localDay(input: string | Date): string {
  const date = typeof input === 'string' ? new Date(input) : input;
  if (Number.isNaN(date.getTime())) throw new Error(`invalid timestamp: ${String(input)}`);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

/** 活跃日集合：按口径过滤 usage 记录后再落到本地自然日。 */
export function activeDays(usage: UsageEntry[], cmds: readonly string[] = ACTIVE_CMDS): Set<string> {
  const days = new Set<string>();
  for (const entry of usage) {
    if (!cmds.includes(entry.cmd)) continue;
    try {
      days.add(localDay(entry.at));
    } catch {
      // 时间戳坏的记录忽略
    }
  }
  return days;
}

/** 'YYYY-MM-DD' → 本地零点，用于窗口比较与日期加减。 */
export function parseDay(day: string): Date {
  const [y, m, d] = day.split('-').map((part) => Number.parseInt(part, 10));
  if (y === undefined || m === undefined || d === undefined || [y, m, d].some(Number.isNaN)) {
    throw new Error(`invalid day: ${day}（期望 YYYY-MM-DD）`);
  }
  return new Date(y, m - 1, d);
}

/** 日期加减（本地自然日）。 */
export function addDays(day: string, delta: number): string {
  const date = parseDay(day);
  date.setDate(date.getDate() + delta);
  return localDay(date);
}

/** 把活跃日裁到最近 window 天（含 today），升序返回。 */
export function withinWindow(days: Iterable<string>, today: string, window: number): string[] {
  const start = parseDay(addDays(today, -(window - 1))).getTime();
  const end = parseDay(today).getTime();
  return [...days]
    .filter((day) => {
      const t = parseDay(day).getTime();
      return t >= start && t <= end;
    })
    .sort();
}

/**
 * usage.jsonl 之外的「真实证据」回填：产物文件只由特定子命令写出，
 * 所以它们的 generated_at / mtime 能证明那天的确跑过分析类命令。
 * 注意 mtime 只保留「最后一次写入」，回填拿到的是下界，不是完整历史 —— 补完这几天之后由 usage.jsonl 接管。
 */
export function artifactDays(outDir: string): Set<string> {
  const days = new Set<string>();
  const stamp = (value: string | Date) => {
    try {
      days.add(localDay(value));
    } catch {
      // 忽略坏时间戳
    }
  };
  for (const name of ['potential.json', 'observed.json']) {
    const path = join(outDir, name);
    if (!existsSync(path)) continue;
    try {
      const parsed = JSON.parse(readFileSync(path, 'utf8')) as { generated_at?: string };
      if (!parsed.generated_at) continue;
      stamp(parsed.generated_at);
    } catch {
      // 图文件不可读时退回到 mtime
      try {
        stamp(statSync(path).mtime);
      } catch {
        // 忽略
      }
    }
  }
  for (const name of ['paths.json', 'chains.json', 'diff.json', 'policy-diff.json', 'capability-diff.json', 'report.md']) {
    const path = join(outDir, name);
    if (!existsSync(path)) continue;
    try {
      stamp(statSync(path).mtime);
    } catch {
      // 忽略
    }
  }
  return days;
}

export function feedbackCounts(outDir: string): { confirmed: number; falsePositive: number } {
  const entries = readFeedback(join(outDir, 'feedback.json'));
  return {
    confirmed: entries.filter((entry) => entry.verdict === 'confirmed').length,
    falsePositive: entries.filter((entry) => entry.verdict === 'false-positive').length,
  };
}

/**
 * H4 判定：给定窗口内的活跃日，算出连续天数和结论。
 *
 * TODO(walden)：这 5-10 行是 H4 的「度量口径」，交给你定。输入输出已固定，替换函数体即可。
 *
 * 需要你拍板的三个点（都会静默改变结论，别默认掉）：
 *   1. 今天还没用，算不算断？形如 [..., 昨天]、今天空白 —— 判 on-track（今天还剩一整天）还是 broken？
 *   2. 断一天是否清零？形如 [09-01..09-05, 09-07..09-09] 中间断一天：streak 从 09-07 重数（3），还是取窗口内最长连续（5）？
 *   3. met 的边界：streak === window 即可；还是要求 activeDays.length === window（窗口内一天都不许断）？
 *
 * 一行参考（从今天往回数，遇到第一个不连续就停）：
 *   let streak = 0;
 *   while (activeDays.includes(addDays(today, -streak))) streak++;
 *   缺口在「今天还没用」——它会让 streak 立刻归零。
 */
export function judgeRetention(_input: RetentionInput): RetentionVerdict {
  throw new Error('judgeRetention 尚未实现：见 apps/cli/src/graph/retention.ts 的 TODO(walden)');
}

/** 人读输出。judgeRetention 未实现时不在这里兜底 —— 缺口径就该显式报错，而不是给个假结论。 */
export function renderRetention(report: RetentionReport): string {
  const label: Record<RetentionStatus, string> = {
    met: '✅ H4 达成：连续使用已满窗口',
    'on-track': '⏳ 进行中',
    broken: '❌ 已中断',
  };
  return [
    `H4 留存（窗口 ${report.window} 天，今天 ${report.today}）`,
    '',
    `- 结论：${label[report.status]}`,
    `- 连续活跃：${report.streak} 天`,
    `- 窗口内活跃：${report.activeDays.length}/${report.window} 天（缺 ${report.missingDays} 天）`,
    `- 上次使用：${report.lastActive ?? '无记录'}`,
    `- 反馈：confirmed ${report.feedback.confirmed} · false-positive ${report.feedback.falsePositive}`,
  ].join('\n');
}
