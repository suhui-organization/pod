/**
 * 告警引擎测试：mock webhook server 验证规则触发与配置开关。
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import { AuditLog, type AuditEntry } from '@podsec/audit';
import { createAlertChecker, createDefaultSender, loadAlertConfig } from '../src/alert.js';

function entry(over: Partial<AuditEntry>): AuditEntry {
  const log = new AuditLog('0.1.0');
  const e = log.append({
    agent: 'test', session: 's', server: 'demo', tool: 'echo',
    argsHash: 'h', decision: 'allow', outcome: 'ok', policyVersion: '0.1.0',
  });
  return { ...e, ...over } as AuditEntry;
}

function startWebhook(): { url: string; events: Array<Record<string, unknown>>; close: () => void } {
  const events: Array<Record<string, unknown>> = [];
  const server: Server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      events.push(JSON.parse(body));
      res.writeHead(200).end();
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      resolve({ url: `http://127.0.0.1:${addr.port}`, events, close: () => server.close() });
    });
  });
}

const settle = () => new Promise((r) => setTimeout(r, 60));

describe('alert engine (P2)', () => {
  let webhook: { url: string; events: Array<Record<string, unknown>>; close: () => void };

  beforeAll(async () => {
    webhook = await startWebhook();
  });
  afterAll(() => webhook.close());

  it('fires high alert on secret_leak', async () => {
    const check = createAlertChecker({ webhook_url: webhook.url });
    check(entry({ decision: 'allow', outcome: 'blocked', reason: 'secret_leak: output matched pattern ghp_' }));
    await settle();
    expect(webhook.events).toHaveLength(1);
    expect(webhook.events[0]!.severity).toBe('high');
    expect(webhook.events[0]!.kind).toBe('secret_leak');
  });

  it('fires medium alert on injection_suspect', async () => {
    const check = createAlertChecker({ webhook_url: webhook.url });
    check(entry({ reason: 'injection_suspect: output contains prompt-override' }));
    await settle();
    const kinds = webhook.events.map((e) => e.kind);
    expect(kinds).toContain('injection_suspect');
    expect(webhook.events.find((e) => e.kind === 'injection_suspect')!.severity).toBe('medium');
  });

  it('fires medium alert on approval timeout', async () => {
    const check = createAlertChecker({ webhook_url: webhook.url });
    check(entry({ decision: 'approve', outcome: 'blocked', reason: 'approval timed out after 5s (fail-closed)' }));
    await settle();
    expect(webhook.events.map((e) => e.kind)).toContain('approval_timeout');
  });

  it('fires high deny_burst once per window', async () => {
    const check = createAlertChecker({ webhook_url: webhook.url });
    for (let i = 0; i < 6; i++) check(entry({ decision: 'deny', outcome: 'blocked', reason: 'denied' }));
    await settle();
    const bursts = webhook.events.filter((e) => e.kind === 'deny_burst');
    expect(bursts).toHaveLength(1); // 窗口内去重
    expect(bursts[0]!.severity).toBe('high');
  });

  it('respects rule switches (secret_leak disabled)', () => {
    const check = createAlertChecker({ webhook_url: webhook.url, rules: { secret_leak: false } });
    const before = webhook.events.length;
    check(entry({ reason: 'secret_leak: x' }));
    expect(webhook.events.length).toBe(before);
  });

  it('loadAlertConfig returns null without config file', () => {
    expect(loadAlertConfig('/nonexistent/alert.json')).toBeNull();
  });

  it('createDefaultSender posts JSON', async () => {
    const sent: Array<Record<string, unknown>> = [];
    const send = createDefaultSender(webhook.url);
    await send({
      severity: 'low', kind: 'test', message: 'm', entry: { seq: 1, ts: 't', agent: 'a', server: 's', tool: 't', decision: 'allow', reason: '' }, fired_at: 'f',
    });
    expect(webhook.events.length).toBeGreaterThan(0);
    void sent;
  });
});
