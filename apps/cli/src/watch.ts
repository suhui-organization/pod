/**
 * pod watch — 长驻审批队列（OPC 缺口 G3：审批疲劳）。
 *
 * 在另一个终端跑 `pod watch`，新审批出现时立即提示：
 * - TTY 交互模式：直接 [y]es / [n]o / [s]kip；
 * - 非交互模式（管道/CI）：打印可复制的 approve/deny 命令；
 * - --once：只做一次快照后退出（脚本与测试用）。
 */
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { decideApproval, listPendingApprovals } from './approval.js';

export interface PendingItem {
  id: string;
  server: string;
  tool: string;
}

export type WatchAnswer = 'approve' | 'deny' | 'skip';

export interface WatchOptions {
  pendingDir: string;
  intervalMs: number;
  once: boolean;
  approver: string;
  interactive: boolean;
  log: (msg: string) => void;
  /** 注入点（单测用） */
  list?: (dir: string) => PendingItem[];
  decide?: (dir: string, id: string, d: { approved: boolean; approver: string; reason?: string }) => void;
  prompt?: (item: PendingItem) => Promise<WatchAnswer>;
  sleep?: (ms: number) => Promise<void>;
}

async function defaultPrompt(item: PendingItem): Promise<WatchAnswer> {
  const rl = createInterface({ input: stdin, output: stdout });
  try {
    const ans = (await rl.question(`  ${item.server}.${item.tool} — [y]es/[n]o/[s]kip: `))
      .trim()
      .toLowerCase();
    if (ans === 'y' || ans === 'yes') return 'approve';
    if (ans === 'n' || ans === 'no') return 'deny';
    return 'skip';
  } finally {
    rl.close();
  }
}

export async function watchPending(opts: WatchOptions): Promise<void> {
  const list = opts.list ?? listPendingApprovals;
  const decide = opts.decide ?? ((dir, id, d) => { decideApproval(dir, id, d); });
  const sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  const prompt = opts.prompt ?? defaultPrompt;
  const seen = new Set<string>();

  for (;;) {
    for (const p of list(opts.pendingDir)) {
      if (seen.has(p.id)) continue;
      seen.add(p.id);
      opts.log(`APPROVAL #${p.id}: server=${p.server} tool=${p.tool}`);
      if (opts.interactive) {
        const answer = await prompt(p);
        if (answer === 'approve') {
          decide(opts.pendingDir, p.id, { approved: true, approver: opts.approver });
          opts.log(`  approved ${p.id} by ${opts.approver}`);
        } else if (answer === 'deny') {
          decide(opts.pendingDir, p.id, { approved: false, approver: opts.approver });
          opts.log(`  denied ${p.id} by ${opts.approver}`);
        } else {
          opts.log(`  skipped ${p.id}`);
        }
      } else {
        opts.log(`  approve: pod approve --id ${p.id} --pending-dir ${opts.pendingDir}`);
        opts.log(`  deny:    pod deny --id ${p.id} --pending-dir ${opts.pendingDir}`);
      }
    }
    if (opts.once) return;
    await sleep(opts.intervalMs);
  }
}
