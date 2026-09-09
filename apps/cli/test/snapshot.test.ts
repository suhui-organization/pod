/**
 * P2 快照/回滚测试：路径收集、创建、恢复、配额跳过。
 */
import { describe, it, expect } from 'vitest';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { collectPathCandidates, createSnapshot, listSnapshots, restoreSnapshot } from '../src/snapshot.js';

describe('collectPathCandidates', () => {
  it('collects existing absolute / ~ / relative paths from nested args', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-snap-home-'));
    const file = join(home, 'a.txt');
    writeFileSync(file, 'x');
    const dir = join(home, 'dir');
    mkdirSync(dir);
    const found = collectPathCandidates(
      { path: file, dirs: ['/nope', '~/a.txt', 'not-a-path'], nested: { p: dir } },
      home,
    );
    expect(found).toEqual(expect.arrayContaining([file, dir]));
    expect(found).not.toContain('/nope');
    expect(found).not.toContain('not-a-path');
    expect(found).toHaveLength(2); // file + dir（~/a.txt 与 path 去重）
  });
});

describe('createSnapshot / restoreSnapshot', () => {
  it('snapshots a file and restores it after modification', () => {
    const root = mkdtempSync(join(tmpdir(), 'pod-snap-'));
    const target = join(root, 'notes.txt');
    writeFileSync(target, 'original', 'utf8');
    const dir = join(root, 'snapshots');

    const manifest = createSnapshot([target], { dir, id: 's1', server: 'fs', tool: 'write_file' });
    expect(manifest.entries).toHaveLength(1);
    expect(manifest.entries[0]!.original).toBe(target);

    writeFileSync(target, 'modified', 'utf8');
    const { restored, missing } = restoreSnapshot(dir, 's1');
    expect(restored).toEqual([target]);
    expect(missing).toEqual([]);
    expect(readFileSync(target, 'utf8')).toBe('original');
  });

  it('snapshots and restores a directory', () => {
    const root = mkdtempSync(join(tmpdir(), 'pod-snap-dir-'));
    const src = join(root, 'project');
    mkdirSync(src);
    writeFileSync(join(src, 'a.txt'), 'A');
    const dir = join(root, 'snapshots');

    createSnapshot([src], { dir, id: 's2', server: 'fs', tool: 'edit' });
    writeFileSync(join(src, 'a.txt'), 'B');
    restoreSnapshot(dir, 's2');
    expect(readFileSync(join(src, 'a.txt'), 'utf8')).toBe('A');
  });

  it('skips paths over the byte quota and records them', () => {
    const root = mkdtempSync(join(tmpdir(), 'pod-snap-cap-'));
    const big = join(root, 'big.bin');
    writeFileSync(big, Buffer.alloc(1024));
    const dir = join(root, 'snapshots');
    const manifest = createSnapshot([big], { dir, id: 's3', server: 'fs', tool: 'write', maxBytes: 10 });
    expect(manifest.entries).toHaveLength(0);
    expect(manifest.skipped.join('\n')).toContain('超过剩余配额');
  });

  it('lists snapshots newest first', () => {
    const root = mkdtempSync(join(tmpdir(), 'pod-snap-list-'));
    const f = join(root, 'a.txt');
    writeFileSync(f, 'x');
    const dir = join(root, 'snapshots');
    createSnapshot([f], { dir, id: 'aaa', server: 's', tool: 't' });
    createSnapshot([f], { dir, id: 'bbb', server: 's', tool: 't' });
    expect(listSnapshots(dir).map((s) => s.id)).toEqual(['bbb', 'aaa']);
  });
});
