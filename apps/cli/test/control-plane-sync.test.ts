// 控制平面事件的「本地动作 → 上云」闭环测试。
//
// 背景：`pod agents enroll` / 接管 / 切执法会在本地留下身份与配置变更事件。
// 这些证据本该能在云端「控制平面」页看到，但事件若写成机器级的 `_control`
// （`~/.pod/audit/_control/control.jsonl`），就会被 pod sync 的
// `e.agent === local_agent` 过滤掉——云端一条都看不到（线上实测
// pod_control_events = 0）。所以事件必须落在**被改动的那个 agent** 的链上。
//
// 这个测试守的就是这条：纳管一个 agent 之后，sync 的收集器必须能把它捞出来。
import { describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { enrollAgent } from '@podsec/console';
import { collectPendingEvents } from '../src/sync.js';

describe('本地纳管事件会随 pod sync 上云', () => {
  it('事件落在被纳管 agent 的链上，并能被该 agent 的绑定收集到', () => {
    const podHome = mkdtempSync(join(tmpdir(), 'pod-cp-sync-'));
    const auditDir = join(podHome, 'audit');
    enrollAgent({ podHome, harness: 'claude-code', agent: 'claude-code', enrolledBy: 'pod ui' });

    // ① 落点：被纳管 agent 的链（不是机器级的 _control）
    expect(existsSync(join(auditDir, 'claude-code', 'control.jsonl'))).toBe(true);
    expect(existsSync(join(auditDir, '_control', 'control.jsonl'))).toBe(false);

    // ② 收集：绑定了 claude-code 的机器，sync 能捞到这两条
    const batches = collectPendingEvents(auditDir, {}, 'claude-code');
    const control = batches.find((b) => b.server === 'control');
    expect(control).toBeTruthy();
    const kinds = control!.events.map((e) => e.kind);
    expect(kinds).toEqual(['identity', 'config-change']);
    expect(control!.events[0]!.reason).toContain('console:enroll:claude-code');
    // 控制平面事件不能混进数据平面（服务端按 kind 分流）
    expect(kinds).not.toContain('tool-call');
  });

  it('别的 agent 的绑定不会捡走它（按 agent 过滤）', () => {
    const podHome = mkdtempSync(join(tmpdir(), 'pod-cp-sync-other-'));
    const auditDir = join(podHome, 'audit');
    enrollAgent({ podHome, harness: 'claude-code', agent: 'claude-code' });
    expect(collectPendingEvents(auditDir, {}, 'codex')).toHaveLength(0);
  });

  it('游标生效：同一批不会被重复推第二遍', () => {
    const podHome = mkdtempSync(join(tmpdir(), 'pod-cp-sync-cursor-'));
    const auditDir = join(podHome, 'audit');
    enrollAgent({ podHome, harness: 'claude-code', agent: 'claude-code' });
    const first = collectPendingEvents(auditDir, {}, 'claude-code').find((b) => b.server === 'control')!;
    const lastHash = first.events[first.events.length - 1]!.hash;
    const second = collectPendingEvents(auditDir, { control: lastHash }, 'claude-code');
    expect(second).toHaveLength(0);
  });
});
