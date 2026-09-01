/**
 * 本地告警引擎（P2，可观测性）。
 *
 * 规则（v0，可判定优先，D2）：
 *   - secret_leak：审计命中密钥拦截 → HIGH
 *   - injection_suspect：审计命中注入信号标记 → MEDIUM
 *   - approval_timeout：审批超时被拒 → MEDIUM
 *   - deny_burst：滑动窗口内 deny 数超阈值（默认 5 次/60s）→ HIGH（窗口内去重）
 *
 * 通知通道：Webhook（POST JSON），可接企业微信/钉钉/Slack 机器人。
 * 配置：~/.pod/alert.json
 *   { "webhook_url": "https://...", "rules": { "secret_leak": true, ...,
 *     "deny_burst": { "threshold": 5, "window_ms": 60000 } } }
 */
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { AuditEntry } from '@podsec/audit';

export interface DenyBurstRule {
  threshold: number;
  window_ms: number;
}

export interface AlertRules {
  secret_leak?: boolean;
  injection_suspect?: boolean;
  approval_timeout?: boolean;
  deny_burst?: DenyBurstRule;
}

export interface AlertConfig {
  webhook_url: string;
  rules?: AlertRules;
}

export interface AlertEvent {
  severity: 'high' | 'medium' | 'low';
  kind: string;
  message: string;
  entry: Pick<AuditEntry, 'seq' | 'ts' | 'agent' | 'server' | 'tool' | 'decision' | 'reason'>;
  fired_at: string;
}

const DEFAULT_BURST: DenyBurstRule = { threshold: 5, window_ms: 60_000 };

export function loadAlertConfig(configPath?: string): AlertConfig | null {
  const path = configPath ?? join(homedir(), '.pod', 'alert.json');
  if (!existsSync(path)) return null;
  try {
    const raw = JSON.parse(readFileSync(path, 'utf8')) as Partial<AlertConfig>;
    if (!raw.webhook_url) return null;
    return { webhook_url: raw.webhook_url, rules: raw.rules ?? {} };
  } catch {
    return null;
  }
}

/** 默认发送器：POST JSON 到 webhook_url（失败由调用方 catch） */
export function createDefaultSender(webhookUrl: string): (e: AlertEvent) => Promise<void> {
  return async (e) => {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(e),
    });
  };
}

/**
 * 创建告警检查器：每条审计 entry 检查规则，触发时发送（fire-and-forget，失败不影响网关）。
 */
export function createAlertChecker(
  cfg: AlertConfig,
  send: (e: AlertEvent) => Promise<void> = createDefaultSender(cfg.webhook_url),
): (entry: AuditEntry) => void {
  const rules = cfg.rules ?? {};
  const burst = rules.deny_burst ?? DEFAULT_BURST;
  const denyWindow: number[] = [];
  let burstFiredAt = 0;

  const fire = (severity: AlertEvent['severity'], kind: string, entry: AuditEntry, message: string) => {
    const event: AlertEvent = {
      severity,
      kind,
      message,
      entry: {
        seq: entry.seq,
        ts: entry.ts,
        agent: entry.agent,
        server: entry.server,
        tool: entry.tool,
        decision: entry.decision,
        reason: entry.reason ?? '',
      },
      fired_at: new Date().toISOString(),
    };
    Promise.resolve(send(event)).catch(() => {});
  };

  return (entry) => {
    const reason = entry.reason ?? '';

    if (rules.secret_leak !== false && reason.includes('secret_leak')) {
      fire('high', 'secret_leak', entry, `工具输出被密钥拦截（${entry.server}.${entry.tool}）`);
    }
    if (rules.injection_suspect !== false && reason.includes('injection_suspect')) {
      fire('medium', 'injection_suspect', entry, `检测到疑似提示注入（${entry.server}.${entry.tool}）`);
    }
    if (rules.approval_timeout !== false && entry.decision === 'approve' && reason.includes('timed out')) {
      fire('medium', 'approval_timeout', entry, `审批超时被拒绝（${entry.server}.${entry.tool}）`);
    }
    if (entry.decision === 'deny') {
      const now = Date.now();
      denyWindow.push(now);
      while (denyWindow.length > 0 && denyWindow[0]! < now - burst.window_ms) denyWindow.shift();
      if (denyWindow.length >= burst.threshold && now - burstFiredAt > burst.window_ms) {
        burstFiredAt = now;
        fire('high', 'deny_burst', entry, `滑动窗口 ${burst.window_ms / 1000}s 内 deny 达到 ${denyWindow.length} 次（阈值 ${burst.threshold}）`);
      }
    }
  };
}
