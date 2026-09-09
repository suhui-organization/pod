import { describe, it, expect } from 'vitest';
import {
  checkServerSource,
  evaluate,
  findHighEntropySecrets,
  lintPolicy,
  matchesSensitivePath,
  shannonEntropy,
  type Policy,
} from './index.js';

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

describe('secrets.deny_input_paths (T2 sensitive path gate)', () => {
  const secretPolicy: Policy = {
    version: '0.1.0',
    agent: 'openclaw-main',
    servers: { filesystem: { allow: ['read_file', '*'] } },
    secrets: { deny_input_paths: ['~/.ssh', '.env', 'credentials', 'id_rsa'] },
  };

  it('denies a read targeting a sensitive path even if the tool is allowed', () => {
    const r = evaluate(secretPolicy, {
      agent: 'openclaw-main',
      server: 'filesystem',
      tool: 'read_file',
      args: { path: '/Users/walden/.ssh/id_rsa' },
    });
    expect(r.decision).toBe('deny');
    expect(r.matched).toBe('secrets-input');
    expect(r.reason).toContain('sensitive path pattern');
  });

  it('normalizes "~/.ssh" so it matches an absolute .ssh path (方案 C)', () => {
    const r = evaluate(secretPolicy, {
      agent: 'openclaw-main',
      server: 'filesystem',
      tool: 'read_file',
      args: { path: '/Users/walden/.ssh/config' },
    });
    expect(r.decision).toBe('deny');
    expect(r.matched).toBe('secrets-input');
    expect(r.reason).toContain('.ssh');
  });

  it('denies when the path appears in nested args (array/object)', () => {
    const r = evaluate(secretPolicy, {
      agent: 'openclaw-main',
      server: 'filesystem',
      tool: 'search_files',
      args: { dirs: ['/tmp', '/app/.env'], pattern: 'x' },
    });
    expect(r.decision).toBe('deny');
  });

  it('allows reads of non-sensitive paths', () => {
    const r = evaluate(secretPolicy, {
      agent: 'openclaw-main',
      server: 'filesystem',
      tool: 'read_file',
      args: { path: '/Users/walden/Workspaces/project/README.md' },
    });
    expect(r.decision).toBe('allow');
  });

  it('explicit deny still wins over sensitive-path denial', () => {
    const p: Policy = {
      version: '0.1.0',
      agent: 'a',
      servers: { s: { deny: ['read_file'] } },
      secrets: { deny_input_paths: ['.env'] },
    };
    const r = evaluate(p, { agent: 'a', server: 's', tool: 'read_file', args: { path: '/x/.env' } });
    expect(r.decision).toBe('deny');
    expect(r.matched).toBe('deny');
  });

  it('approve rules still work when no sensitive path is hit', () => {
    const p: Policy = {
      version: '0.1.0',
      agent: 'a',
      servers: { s: { approve: ['write_file'] } },
      secrets: { deny_input_paths: ['.env'] },
    };
    const r = evaluate(p, { agent: 'a', server: 's', tool: 'write_file', args: { path: '/x/notes.md' } });
    expect(r.decision).toBe('approve');
  });

  it('matches a dotfile variant (".env" hits ".env.local")', () => {
    expect(matchesSensitivePath('/app/.env.local', '.env')).toBe(true);
  });

  it('does not match a segment prefix (".ssh" must not hit ".ssh-backup")', () => {
    expect(matchesSensitivePath('/tmp/.ssh-backup/notes.txt', '.ssh')).toBe(false);
  });

  it('matches a multi-segment pattern anywhere in the path', () => {
    expect(matchesSensitivePath('/srv/app/config/credentials.json', 'config/credentials')).toBe(true);
  });
});

describe('lintPolicy (P1, T9 misconfiguration)', () => {
  it('flags fail-open default, wildcard allow and missing secrets', () => {
    const p: Policy = {
      version: '0.1.0',
      agent: 'a',
      defaultDecision: 'allow',
      servers: { s: { allow: ['*'] } },
    };
    const issues = lintPolicy(p);
    const sev = issues.map((i) => i.severity);
    expect(sev).toContain('warn');
    expect(issues.some((i) => i.message.includes('fail-open'))).toBe(true);
    expect(issues.some((i) => i.message.includes('"*"'))).toBe(true);
    expect(issues.some((i) => i.message.includes('secrets 规则'))).toBe(true);
  });

  it('flags invalid regex in deny_output_matching as error', () => {
    const p: Policy = {
      version: '0.1.0',
      agent: 'a',
      servers: { s: { allow: ['x'] } },
      secrets: { deny_output_matching: ['[unclosed'] },
    };
    const issues = lintPolicy(p);
    expect(issues.some((i) => i.severity === 'error' && i.message.includes('非法正则'))).toBe(true);
  });

  it('passes a healthy baseline policy with no errors', () => {
    const p: Policy = {
      version: '0.1.0',
      agent: 'a',
      defaultDecision: 'deny',
      servers: { filesystem: { allow: ['read_file'], approve: ['write_file'], deny: ['delete_file'] } },
      secrets: { deny_input_paths: ['.env'], deny_output_matching: ['ghp_[A-Za-z0-9]{36}'] },
    };
    const issues = lintPolicy(p);
    expect(issues.filter((i) => i.severity === 'error')).toHaveLength(0);
  });

  it('hints that "~/" prefixes are normalized when matching', () => {
    const p: Policy = {
      version: '0.1.0',
      agent: 'a',
      servers: { s: { allow: ['x'] } },
      secrets: { deny_input_paths: ['~/.ssh'] },
    };
    const issues = lintPolicy(p);
    expect(issues.some((i) => i.where === 'secrets.deny_input_paths' && i.message.includes('归一化'))).toBe(true);
  });
});

describe('checkServerSource (T4 supply-chain whitelist)', () => {
  it('accepts matching command source', () => {
    expect(checkServerSource({ command: 'mcp-server-filesystem' }, 'mcp-server-filesystem', ['/tmp'])).toBeNull();
  });

  it('rejects mismatched command', () => {
    const r = checkServerSource({ command: 'mcp-server-filesystem' }, 'evil-server', []);
    expect(r).toContain('source.command 不匹配');
  });

  it('accepts matching npx package with pinned version', () => {
    expect(
      checkServerSource({ package: '@modelcontextprotocol/server-github', version: '1.2.3' }, 'npx', ['-y', '@modelcontextprotocol/server-github@1.2.3']),
    ).toBeNull();
  });

  it('rejects unpinned version when version required', () => {
    const r = checkServerSource({ package: 'pkg', version: '1.0.0' }, 'npx', ['-y', 'pkg@latest']);
    expect(r).toContain('source.version 不匹配');
  });

  it('rejects different package', () => {
    const r = checkServerSource({ package: 'good-pkg' }, 'npx', ['-y', 'evil-pkg']);
    expect(r).toContain('source.package 不匹配');
  });

  it('rejects npx requirement when command is not npx', () => {
    const r = checkServerSource({ package: 'pkg' }, 'local-bin', []);
    expect(r).toContain('不是 npx 来源');
  });

  it('no source declared = no restriction', () => {
    expect(checkServerSource(undefined, 'anything', [])).toBeNull();
  });

  it('lint suggests declaring source', () => {
    const p: Policy = { version: '0.1.0', agent: 'a', servers: { s: { allow: ['x'] } } };
    const issues = lintPolicy(p);
    expect(issues.some((i) => i.message.includes('来源白名单'))).toBe(true);
  });
});

describe('findHighEntropySecrets (P2 output entropy)', () => {
  const SECRET = 'aB3xK9mQ2pR7sT4vW8yZ1nC6';

  it('computes shannon entropy', () => {
    expect(shannonEntropy('aaaa')).toBe(0);
    expect(shannonEntropy('abcd')).toBe(2);
  });

  it('detects a base64-like secret', () => {
    const hits = findHighEntropySecrets(`token ${SECRET}`, { enabled: true });
    expect(hits).toHaveLength(1);
    expect(hits[0]!.length).toBe(SECRET.length);
    expect(hits[0]!.entropy).toBeGreaterThan(4);
    expect(hits[0]!.sample).not.toBe(SECRET);
  });

  it('does not flag hex hashes (entropy ceiling 4.0)', () => {
    const hex = 'a3f9c2e1b7d4086f5a2c9e1d3b7f0a4c8e2d6b1f';
    expect(findHighEntropySecrets(hex, { enabled: true })).toHaveLength(0);
  });

  it('is off by default and honors allow_patterns', () => {
    expect(findHighEntropySecrets(SECRET)).toHaveLength(0);
    expect(findHighEntropySecrets(SECRET, { enabled: true, allow_patterns: ['^aB3'] })).toHaveLength(0);
  });

  it('lint recommends enabling entropy detection', () => {
    const p: Policy = {
      version: '0.1.0',
      agent: 'a',
      servers: { s: { allow: ['x'] } },
      secrets: { deny_input_paths: ['.env'], deny_output_matching: ['sk-[A-Za-z0-9]{20,}'] },
    };
    expect(lintPolicy(p).some((i) => i.where === 'secrets.entropy' && i.message.includes('熵检测'))).toBe(true);
  });
});
