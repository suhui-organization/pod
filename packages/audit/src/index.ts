import { createHash } from 'node:crypto';
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

export type Decision = 'allow' | 'deny' | 'approve';
export type Outcome = 'ok' | 'error' | 'blocked';

/**
 * 一条审计记录。
 *
 * 设计原则（threat-model.md T7 / T2）：
 * - 敏感内容（args/output）默认只存哈希，不存原文；
 * - prevHash + hash 构成 SHA-256 哈希链，篡改任意一条会使 verify 失败；
 * - 字段顺序与计算无关：哈希基于 stableStringify（键排序）后的正文。
 */
export interface AuditEntry {
  seq: number;
  ts: string;
  agent: string;
  session: string;
  server: string;
  tool: string;
  argsHash: string;
  decision: Decision;
  outcome: Outcome;
  reason?: string;
  approver?: string;
  outputHash?: string;
  policyVersion: string;
  /** false = 仅记录未强制执行（pod record 模式）；缺省视为 true */
  enforced?: boolean;
  /** 上一条记录的 hash；链首为 '' */
  prevHash: string;
  /** sha256(正文)，正文 = 本记录除 hash 外的所有字段 */
  hash: string;
}

/** 追加一条记录所需的字段（seq/ts/prevHash/hash 由 AuditLog 计算） */
export type NewAuditEntry = Omit<AuditEntry, 'seq' | 'ts' | 'prevHash' | 'hash'>;

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/** 对任意值的确定性哈希（键排序，与字段顺序无关） */
export function hashValue(value: unknown): string {
  return sha256Hex(stableStringify(value));
}

/** 键排序的稳定 JSON 序列化；数组保序。 */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`;
}

export interface AuditLogOptions {
  now?: () => Date;
  /** 每次 append 后回调（用于增量落盘） */
  onAppend?: (entry: AuditEntry) => void;
}

export class AuditLog {
  readonly entries: AuditEntry[] = [];
  private readonly now: () => Date;
  private readonly onAppend?: (entry: AuditEntry) => void;

  constructor(
    public readonly policyVersion: string,
    options: AuditLogOptions = {},
  ) {
    this.now = options.now ?? (() => new Date());
    this.onAppend = options.onAppend;
  }

  append(input: NewAuditEntry): AuditEntry {
    const prev = this.entries[this.entries.length - 1];
    const entry: AuditEntry = {
      ...input,
      seq: prev ? prev.seq + 1 : 1,
      ts: this.now().toISOString(),
      prevHash: prev ? prev.hash : '',
      hash: '',
    };
    // 值为 undefined 的键会被 JSON.stringify 省略落盘，但 stableStringify
    // 会输出 "key":undefined —— 若不剔除，append 与 verify 的哈希正文不一致。
    // 必须删除所有 undefined 键（含 enforced 及可选字段如 approver/reason）。
    for (const key of Object.keys(entry)) {
      if ((entry as unknown as Record<string, unknown>)[key] === undefined) {
        delete (entry as unknown as Record<string, unknown>)[key];
      }
    }
    entry.hash = hashEntryBody(entry);
    this.entries.push(entry);
    this.onAppend?.(entry);
    return entry;
  }

  toJSONL(): string {
    if (this.entries.length === 0) return '';
    return this.entries.map((e) => JSON.stringify(e)).join('\n') + '\n';
  }

  static fromJSONL(text: string, policyVersion: string, options?: AuditLogOptions): AuditLog {
    const log = new AuditLog(policyVersion, options);
    for (const line of text.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      log.entries.push(JSON.parse(trimmed) as AuditEntry);
    }
    return log;
  }

  /** 校验整条哈希链；返回第一条断裂记录的 seq */
  verify(): { ok: boolean; firstBrokenSeq?: number } {
    let prevHash = '';
    for (const entry of this.entries) {
      const { hash, ...body } = entry;
      const expected = sha256Hex(stableStringify(body));
      if (hash !== expected || entry.prevHash !== prevHash) {
        return { ok: false, firstBrokenSeq: entry.seq };
      }
      prevHash = hash;
    }
    return { ok: true };
  }
}

export function hashEntryBody(entry: Omit<AuditEntry, 'hash'>): string {
  // 运行期 entry 对象可能仍携带 hash 字段（如 append 中 hash 尚未赋值），
  // 必须显式剔除，保证与 verify() 的正文口径一致。
  const { hash: _omit, ...body } = entry as AuditEntry;
  return sha256Hex(stableStringify(body));
}

/** 追加一条记录到 JSONL 文件（创建父目录） */
export function appendToAuditFile(path: string, entry: AuditEntry): void {
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, JSON.stringify(entry) + '\n', 'utf8');
}

/** 从 JSONL 文件加载并校验（校验失败抛出）；options 用于恢复 onAppend（续链场景） */
export function loadAuditFile(path: string, policyVersion: string, options?: AuditLogOptions): AuditLog {
  const text = readFileSync(path, 'utf8');
  const log = AuditLog.fromJSONL(text, policyVersion, options);
  const check = log.verify();
  if (!check.ok) {
    throw new Error(`audit chain broken at seq ${check.firstBrokenSeq}: ${path}`);
  }
  return log;
}

/** 原子写入整份审计（调试/导出用） */
export function writeAuditFile(path: string, log: AuditLog): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, log.toJSONL(), 'utf8');
}
