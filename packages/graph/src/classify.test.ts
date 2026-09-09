import { describe, expect, it } from 'vitest';
import { classifyTool, tokenize } from './classify.js';

const tool = (name: string, inputSchema?: unknown) => ({ name, inputSchema });

describe('tokenize', () => {
  it('splits snake/kebab/camel/dot', () => {
    expect(tokenize('read_file')).toEqual(['read', 'file']);
    expect(tokenize('createPullRequest')).toEqual(['create', 'pull', 'request']);
    expect(tokenize('fs.read')).toEqual(['fs', 'read']);
  });
});

describe('classifyTool', () => {
  it('classifies destructive / exec / external / read tools', () => {
    expect(classifyTool(tool('delete_file')).assertions[0]?.capability).toBe('destructive-write');
    expect(classifyTool(tool('execute_command')).assertions[0]?.capability).toBe('exec');
    expect(classifyTool(tool('send_email')).assertions[0]?.capability).toBe('external-communication');
    expect(classifyTool(tool('read_file', { type: 'object', properties: { path: { type: 'string' } } })).assertions
      .map((a) => a.capability)
      .sort()).toEqual(['read-private-data', 'read-secret']);
  });

  it('classifies http_request as ambiguous (untrusted input + external communication)', () => {
    const result = classifyTool(
      tool('http_request', {
        type: 'object',
        properties: { url: { type: 'string' }, method: { type: 'string' }, body: { type: 'string' } },
      }),
    );
    expect(result.assertions.map((a) => a.capability).sort()).toEqual([
      'external-communication',
      'read-untrusted-input',
    ]);
  });

  it('honors explicit overrides with confidence 1 and origin policy', () => {
    const result = classifyTool(tool('acme_sync'), ['external-communication']);
    expect(result.assertions).toEqual([
      {
        capability: 'external-communication',
        confidence: 1,
        origin: 'policy',
        evidence: ['policy override'],
      },
    ]);
  });

  it('marks unknown tools as unclassified and detects write context', () => {
    expect(classifyTool(tool('acme_sync')).unclassified).toBe(true);
    expect(classifyTool(tool('write_file')).writeContext).toBe(true);
  });
});
