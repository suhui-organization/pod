import { describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { discoverTargets } from '../src/onboard.js';

function writeJson(path: string, value: unknown): void {
  writeFileSync(path, JSON.stringify(value), 'utf8');
}

describe('Claude Code config discovery', () => {
  it('reads top-level and project-scoped mcpServers from ~/.claude.json', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-claude-'));
    writeJson(join(home, '.claude.json'), {
      mcpServers: { top: { command: 'node', args: ['top.js'] } },
      projects: {
        '/proj': { mcpServers: { nested: { command: 'node', args: ['nested.js'] } } },
      },
    });
    const withProject = discoverTargets({ home, includeProject: true });
    const names = withProject.flatMap((t) => t.servers.map((s) => s.name)).sort();
    expect(names).toEqual(['nested', 'top']);

    const withoutProject = discoverTargets({ home });
    expect(withoutProject.flatMap((t) => t.servers.map((s) => s.name))).toEqual(['top']);
  });

  it('reads ~/.claude/settings.json and <cwd>/.mcp.json', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-claude-settings-'));
    mkdirSync(join(home, '.claude'), { recursive: true });
    writeJson(join(home, '.claude', 'settings.json'), {
      mcpServers: { settings: { command: 'node', args: ['settings.js'] } },
    });
    const cwd = mkdtempSync(join(tmpdir(), 'pod-claude-project-'));
    writeJson(join(cwd, '.mcp.json'), {
      mcpServers: { project: { command: 'node', args: ['project.js'] } },
    });
    const targets = discoverTargets({ home, cwd, includeProject: true });
    const names = targets.flatMap((t) => t.servers.map((s) => s.name)).sort();
    expect(names).toEqual(['project', 'settings']);
  });
});
