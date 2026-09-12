/**
 * 高危写操作快照 / 回滚（P2，OPC 缺口：approve 只能批，不能撤）。
 *
 * 思路：网关在真正调用上游前，把参数里出现的、真实存在的路径复制到
 * ~/.pod/snapshots/<id>/，审计记录 snapshot id；出错时 `pod rollback --id <id>` 一键恢复。
 *
 * 边界（说清楚不夸大）：
 * - 只快照参数里能识别为路径、且当前存在的文件/目录；
 * - 有总量与条目上限（默认 50MB / 100 条），超限跳过并记录；
 * - 不是文件系统级快照，无法覆盖工具自己生成的中间文件或网络副作用。
 */
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { t } from '@podsec/i18n';

export interface SnapshotEntry {
  original: string;
  /** 相对 snapshot 根目录的存储路径 */
  stored: string;
  bytes: number;
  kind: 'file' | 'dir';
}

export interface SnapshotManifest {
  id: string;
  created_at: string;
  server: string;
  tool: string;
  entries: SnapshotEntry[];
  skipped: string[];
}

export interface SnapshotOptions {
  dir: string;
  id: string;
  server: string;
  tool: string;
  maxBytes?: number;
  maxEntries?: number;
}

function looksLikePath(s: string): boolean {
  return (
    s.length > 0 &&
    s.length < 4096 &&
    (s.startsWith('/') || s.startsWith('~/') || s.startsWith('./') || s.startsWith('../'))
  );
}

/** 递归收集参数中"看起来像路径且真实存在"的字符串（去重、展开 ~） */
export function collectPathCandidates(args: unknown, home = homedir()): string[] {
  const out = new Set<string>();
  const visit = (v: unknown): void => {
    if (typeof v === 'string') {
      if (!looksLikePath(v)) return;
      const expanded = v.startsWith('~') ? join(home, v.slice(1)) : v;
      const abs = resolve(expanded);
      if (existsSync(abs)) out.add(abs);
    } else if (Array.isArray(v)) {
      for (const x of v) visit(x);
    } else if (v !== null && typeof v === 'object') {
      for (const x of Object.values(v)) visit(x);
    }
  };
  visit(args);
  return [...out];
}

function sizeOf(path: string, cap: number): number {
  try {
    const st = statSync(path);
    if (st.isFile()) return st.size;
    if (st.isDirectory()) {
      let total = 0;
      for (const f of readdirSync(path)) {
        total += sizeOf(join(path, f), Math.max(0, cap - total));
        if (total > cap) return total;
      }
      return total;
    }
  } catch {
    return 0;
  }
  return 0;
}

/** 创建快照；返回 manifest（超限的路径记在 skipped） */
export function createSnapshot(paths: string[], opts: SnapshotOptions): SnapshotManifest {
  const maxBytes = opts.maxBytes ?? 50 * 1024 * 1024;
  const maxEntries = opts.maxEntries ?? 100;
  const root = join(opts.dir, opts.id);
  mkdirSync(join(root, 'files'), { recursive: true, mode: 0o700 });
  const manifest: SnapshotManifest = {
    id: opts.id,
    created_at: new Date().toISOString(),
    server: opts.server,
    tool: opts.tool,
    entries: [],
    skipped: [],
  };
  let totalBytes = 0;
  let index = 0;
  for (const p of paths) {
    if (manifest.entries.length >= maxEntries) {
      manifest.skipped.push(t('{path}（超过 {max} 个条目上限）', { path: p, max: maxEntries }));
      continue;
    }
    let st;
    try {
      st = statSync(p);
    } catch {
      manifest.skipped.push(t('{path}（不可读）', { path: p }));
      continue;
    }
    const size = sizeOf(p, maxBytes - totalBytes);
    if (size > maxBytes - totalBytes) {
      manifest.skipped.push(
        t('{path}（{size} bytes 超过剩余配额 {quota}）', { path: p, size, quota: maxBytes - totalBytes }),
      );
      continue;
    }
    const stored = join('files', `${String(index++).padStart(3, '0')}-${basename(p) || 'root'}`);
    cpSync(p, join(root, stored), { recursive: st.isDirectory(), force: true });
    manifest.entries.push({
      original: p,
      stored,
      bytes: size,
      kind: st.isDirectory() ? 'dir' : 'file',
    });
    totalBytes += size;
  }
  writeFileSync(join(root, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  return manifest;
}

export function listSnapshots(dir: string): SnapshotManifest[] {
  if (!existsSync(dir)) return [];
  const out: SnapshotManifest[] = [];
  for (const id of readdirSync(dir).sort().reverse()) {
    const f = join(dir, id, 'manifest.json');
    if (!existsSync(f)) continue;
    try {
      out.push(JSON.parse(readFileSync(f, 'utf8')) as SnapshotManifest);
    } catch {
      // 损坏的 manifest 跳过
    }
  }
  return out;
}

/** 从快照恢复（覆盖原路径） */
export function restoreSnapshot(dir: string, id: string): { restored: string[]; missing: string[] } {
  const f = join(dir, id, 'manifest.json');
  if (!existsSync(f)) throw new Error(`snapshot "${id}" not found in ${dir}`);
  const manifest = JSON.parse(readFileSync(f, 'utf8')) as SnapshotManifest;
  const restored: string[] = [];
  const missing: string[] = [];
  for (const e of manifest.entries) {
    const src = join(dir, id, e.stored);
    if (!existsSync(src)) {
      missing.push(e.original);
      continue;
    }
    mkdirSync(dirname(e.original), { recursive: true });
    cpSync(src, e.original, { recursive: e.kind === 'dir', force: true });
    restored.push(e.original);
  }
  return { restored, missing };
}
