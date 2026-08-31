import { describe, it, expect } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  maskSecret,
  parseNpxPackage,
  scanSecretsInText,
  inspectMcpServer,
  scanMachine,
  renderMarkdown,
} from './index.js';

describe('maskSecret', () => {
  it('masks long secrets keeping prefix and suffix', () => {
    expect(maskSecret('ghp_abcdefghijklmnopqrstuvwxyzABCDEF')).toBe('ghp_…EF');
  });
  it('fully masks short values', () => {
    expect(maskSecret('short')).toBe('***');
  });
});

describe('parseNpxPackage', () => {
  it('parses pinned version', () => {
    expect(parseNpxPackage(['npx', '-y', '@upstash/context7-mcp@1.2.3'])).toEqual({
      name: '@upstash/context7-mcp',
      version: '1.2.3',
    });
  });
  it('parses latest as unpinned', () => {
    expect(parseNpxPackage(['npx', '-y', '@playwright/mcp@latest'])).toEqual({
      name: '@playwright/mcp',
      version: 'latest',
    });
  });
  it('returns null version when not pinned', () => {
    expect(parseNpxPackage(['npx', '-y', 'firecrawl-mcp'])).toEqual({ name: 'firecrawl-mcp', version: null });
  });
  it('skips flags before the package name', () => {
    expect(parseNpxPackage(['npx', '-y', '--package', 'pkg@1', 'run'])).toEqual({ name: 'pkg', version: '1' });
  });
  it('returns null for non-npx commands', () => {
    expect(parseNpxPackage(['mcp-server-filesystem', '/path'])).toBeNull();
    expect(parseNpxPackage(['node', 'server.js'])).toBeNull();
  });
});

describe('scanSecretsInText', () => {
  it('finds github PAT and masks it', () => {
    const hits = scanSecretsInText('token=ghp_abcdefghijklmnopqrstuvwxyzABCDEF123456', 'x');
    expect(hits).toHaveLength(1);
    expect(hits[0]!.category).toBe('github-pat');
    expect(hits[0]!.masked).toMatch(/^ghp_/);
    expect(hits[0]!.masked).not.toContain('abcdefghijklmnopqrstuvwxyz');
  });
  it('finds multiple categories', () => {
    const hits = scanSecretsInText('a=sk-proj-0123456789abcdefghij b=AKIA0123456789ABCDEF', 'x');
    const cats = hits.map((h) => h.category).sort();
    expect(cats).toContain('openai');
    expect(cats).toContain('aws-access-key');
  });
  it('deduplicates identical secrets', () => {
    const hits = scanSecretsInText('x=ghp_0123456789012345678901234567890123456 y=ghp_0123456789012345678901234567890123456', 'x');
    expect(hits).toHaveLength(1);
  });
  it('ignores non-secret text', () => {
    expect(scanSecretsInText('no secrets here 12345', 'x')).toHaveLength(0);
  });
});

describe('inspectMcpServer', () => {
  it('flags unpinned npx package', () => {
    const info = inspectMcpServer({ name: 'github', command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'] });
    expect(info.risks.length).toBeGreaterThan(0);
    expect(info.risks[0]).toContain('未锁定');
  });
  it('flags @latest', () => {
    const info = inspectMcpServer({ name: 'playwright', command: 'npx', args: ['-y', '@playwright/mcp@latest'] });
    expect(info.risks[0]).toContain('@latest');
  });
  it('accepts local bin without risk', () => {
    const info = inspectMcpServer({ name: 'filesystem', command: 'mcp-server-filesystem', args: ['/tmp'] });
    expect(info.risks).toHaveLength(0);
    expect(info.npxPackage).toBeUndefined();
  });
  it('accepts pinned version', () => {
    const info = inspectMcpServer({ name: 'x', command: 'npx', args: ['-y', 'pkg@1.2.3'] });
    expect(info.risks).toHaveLength(0);
  });
});

describe('scanMachine (mock home)', () => {
  function makeHome(): string {
    const home = mkdtempSync(join(tmpdir(), 'pod-scan-'));
    mkdirSync(join(home, '.dsh'), { recursive: true });
    mkdirSync(join(home, '.openclaw'), { recursive: true });
    mkdirSync(join(home, '.claude'), { recursive: true });
    mkdirSync(join(home, '.codex'), { recursive: true });
    writeFileSync(join(home, '.claude.json'), '{}', 'utf8');
    writeFileSync(
      join(home, '.dsh/mcp-manager.json'),
      JSON.stringify({
        servers: [
          { name: 'filesystem', command: 'mcp-server-filesystem', args: ['/tmp'], env: {} },
          { name: 'github', command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'], env: { GITHUB_PERSONAL_ACCESS_TOKEN: 'ghp_0123456789012345678901234567890123456' } },
          { name: 'pinned', command: 'npx', args: ['-y', 'safe@1.0.0'], env: {} },
        ],
      }),
      'utf8',
    );
    return home;
  }

  it('discovers agents and MCP servers, flags unpinned and secrets', () => {
    const result = scanMachine({ home: makeHome() });
    // agents
    const found = result.agents.filter((a) => a.found).map((a) => a.platform);
    expect(found).toContain('DeepSeek Harness (DSH)');
    expect(found).toContain('OpenClaw');
    expect(found).toContain('Claude Code');
    // servers
    expect(result.mcpServers.map((s) => s.name).sort()).toEqual(['filesystem', 'github', 'pinned']);
    // findings: 未锁定版本 + 明文密钥
    const severities = result.findings.map((f) => f.severity);
    expect(severities).toContain('medium');
    expect(severities).toContain('high');
    const secret = result.secrets[0]!;
    expect(secret.key).toBe('GITHUB_PERSONAL_ACCESS_TOKEN');
    expect(secret.masked).not.toContain('0123456789012345678901234567890123456');
    expect(renderMarkdown(result)).toContain('## 4. 风险汇总');
  });

  it('reports no risks for a clean home', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-scan-clean-'));
    mkdirSync(join(home, '.dsh'), { recursive: true });
    writeFileSync(
      join(home, '.dsh/mcp-manager.json'),
      JSON.stringify({ servers: [{ name: 'ok', command: 'bin', args: [], env: {} }] }),
      'utf8',
    );
    const result = scanMachine({ home });
    expect(result.findings).toHaveLength(0);
    expect(result.secrets).toHaveLength(0);
  });

  it('survives an unreadable manager file with a high finding', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-scan-bad-'));
    mkdirSync(join(home, '.dsh'), { recursive: true });
    writeFileSync(join(home, '.dsh/mcp-manager.json'), '{not json', 'utf8');
    const result = scanMachine({ home });
    expect(result.findings.some((f) => f.severity === 'high' && f.message.includes('不是合法 JSON'))).toBe(true);
  });
});
