/**
 * guard 基线：只存**指纹**，不存配置原文（与 posture 基线同一隐私口径）。
 *
 * 存什么、为什么：
 * - server 指纹（command+args）→ 用来发现"同名 server 被换成另一个包"（AG-14）；
 * - 钩子指纹 → 用来发现"插件更新后钩子被静默改写"（AG-05 的变化侧）。
 *
 * 不存 env 值、不存 URL 全文——基线文件本身不能变成第二个泄露面。
 */
import type { Facts } from './types.js';

export interface GuardBaseline {
  v: 1;
  createdAt: string;
  home: string;
  /** key = `<harness>/<server>`，value = command+args 指纹 */
  servers: Record<string, string>;
  /** key = `<file>#<event>#<index>`，value = 钩子内容指纹 */
  hooks: Record<string, string>;
}

export function serverKey(harness: string, name: string): string {
  return `${harness}/${name}`;
}

export function hookKey(file: string, event: string, index: number): string {
  return `${file}#${event}#${index}`;
}

export function buildGuardBaseline(facts: Facts, opts: { home: string; now?: Date }): GuardBaseline {
  const servers: Record<string, string> = {};
  for (const server of facts.servers) {
    servers[serverKey(server.harness, server.name)] = server.fingerprint;
  }
  const hooks: Record<string, string> = {};
  for (const hook of facts.hooks) {
    hooks[hookKey(hook.file, hook.event, hook.index)] = hook.fingerprint;
  }
  return {
    v: 1,
    createdAt: (opts.now ?? new Date()).toISOString(),
    home: opts.home,
    servers,
    hooks,
  };
}

export function parseGuardBaseline(text: string): GuardBaseline {
  const raw = JSON.parse(text) as Partial<GuardBaseline>;
  if (raw.v !== 1 || typeof raw.servers !== 'object' || raw.servers === null) {
    throw new Error('基线文件格式不支持（期望 v=1）');
  }
  return {
    v: 1,
    createdAt: raw.createdAt ?? '',
    home: raw.home ?? '',
    servers: raw.servers ?? {},
    hooks: raw.hooks ?? {},
  };
}
