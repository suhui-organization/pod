import { describe, it, expect } from 'vitest';
import { evaluate, type Policy } from './index.js';

const policy: Policy = {
  version: '0.1.0',
  agent: 'openclaw-main',
  defaultDecision: 'deny',
  servers: {
    filesystem: {
      allow: ['read_file', 'list_directory', 'search_files'],
      approve: ['write_file', 'edit_file'],
      deny: ['delete_file'],
    },
    github: {
      allow: ['*'],
      deny: ['delete_repository'],
    },
  },
};

describe('evaluate', () => {
  it('allows explicitly authorized tools', () => {
    const r = evaluate(policy, { agent: 'openclaw-main', server: 'filesystem', tool: 'read_file' });
    expect(r.decision).toBe('allow');
    expect(r.matched).toBe('allow');
  });

  it('denies explicitly denied tools (deny wins over allow)', () => {
    const r = evaluate(policy, { agent: 'openclaw-main', server: 'github', tool: 'delete_repository' });
    expect(r.decision).toBe('deny');
    expect(r.matched).toBe('deny');
  });

  it('approves tools that require approval', () => {
    const r = evaluate(policy, { agent: 'openclaw-main', server: 'filesystem', tool: 'write_file' });
    expect(r.decision).toBe('approve');
    expect(r.matched).toBe('approve');
  });

  it('is fail-closed for unlisted tools', () => {
    const r = evaluate(policy, { agent: 'openclaw-main', server: 'filesystem', tool: 'unlisted_tool' });
    expect(r.decision).toBe('deny');
    expect(r.matched).toBe('default');
  });

  it('is fail-closed for unregistered servers', () => {
    const r = evaluate(policy, { agent: 'openclaw-main', server: 'unknown-server', tool: 'read_file' });
    expect(r.decision).toBe('deny');
    expect(r.matched).toBe('server');
  });

  it('honors custom defaultDecision for unregistered servers', () => {
    const p: Policy = { ...policy, defaultDecision: 'approve' };
    const r = evaluate(p, { agent: 'openclaw-main', server: 'unknown-server', tool: 'x' });
    expect(r.decision).toBe('approve');
  });

  it('rejects calls when the agent identity does not match the policy', () => {
    const r = evaluate(policy, { agent: 'cursor', server: 'filesystem', tool: 'read_file' });
    expect(r.decision).toBe('deny');
    expect(r.matched).toBe('agent');
  });

  it('supports "*" wildcard in allow and deny', () => {
    const p: Policy = {
      version: '0.1.0',
      agent: 'a',
      servers: { s: { allow: ['*'] } },
    };
    expect(evaluate(p, { agent: 'a', server: 's', tool: 'anything' }).decision).toBe('allow');
  });

  it('deny beats approve when both match', () => {
    const p: Policy = {
      version: '0.1.0',
      agent: 'a',
      servers: { s: { allow: ['x'], approve: ['x'], deny: ['x'] } },
    };
    const r = evaluate(p, { agent: 'a', server: 's', tool: 'x' });
    expect(r.decision).toBe('deny');
  });

  it('approve beats allow when both match', () => {
    const p: Policy = {
      version: '0.1.0',
      agent: 'a',
      servers: { s: { allow: ['x'], approve: ['x'] } },
    };
    expect(evaluate(p, { agent: 'a', server: 's', tool: 'x' }).decision).toBe('approve');
  });
});
