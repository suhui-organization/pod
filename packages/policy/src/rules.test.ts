import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DEFAULT_RULES, loadRules, mergeRules, RuleSetError, validateRules } from './rules.js';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'pod-rules-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('规则文件的合并语义', () => {
  it('对象深合并，数组整体替换（用户写 [] 就是关掉这项）', () => {
    const merged = mergeRules(DEFAULT_RULES, {
      hookRisk: { riskPatterns: [] },
      anomaly: { delegationsPerWindow: 99 },
    });
    expect(merged.hookRisk.riskPatterns).toEqual([]);
    // 同一对象里的其它键保留默认值
    expect(merged.hookRisk.trustedSources).toEqual(DEFAULT_RULES.hookRisk.trustedSources);
    expect(merged.anomaly.delegationsPerWindow).toBe(99);
    expect(merged.anomaly.windowMinutes).toBe(DEFAULT_RULES.anomaly.windowMinutes);
  });

  it('文件不存在时用默认值，不报错', () => {
    expect(loadRules(join(dir, 'nope.json')).hookRisk.riskPatterns.length).toBeGreaterThan(0);
    expect(loadRules(undefined)).toEqual(DEFAULT_RULES);
  });
});

describe('fail-closed：规则写错必须报错，不能静默退回默认值', () => {
  function writeRules(content: string): string {
    const path = join(dir, 'rules.json');
    writeFileSync(path, content, 'utf8');
    return path;
  }

  it('非法 JSON 报错', () => {
    expect(() => loadRules(writeRules('{ not json'))).toThrow(RuleSetError);
  });

  it('非法正则报错', () => {
    const path = writeRules(JSON.stringify({ hookRisk: { riskPatterns: [{ id: 'bad', re: '([', severity: 'high' }] } }));
    expect(() => loadRules(path)).toThrow(/不是合法正则/);
  });

  it('非法严重级别与算法报错', () => {
    expect(() =>
      validateRules(
        mergeRules(DEFAULT_RULES, { hookRisk: { riskPatterns: [{ id: 'x', re: 'x', severity: 'urgent' }] } }),
      ),
    ).toThrow(/severity/);
    expect(() => validateRules(mergeRules(DEFAULT_RULES, { identity: { algorithm: 'rsa' } }))).toThrow(/ed25519/);
  });
});
