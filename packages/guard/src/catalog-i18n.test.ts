/**
 * 威胁目录的英文完整性。
 *
 * 为什么单独一个测试，而不是靠 `scripts/i18n-coverage.sh`：目录文案是**数据**，
 * 渲染时才按 `t(entry.title)` 查表，静态的 `t('…')` 抽取看不见这些调用点。
 * 覆盖率脚本会因此把它们误报成僵尸键，也就无法用来检查"翻没翻"。
 *
 * 所以这里把同一件事变成 CI 门禁：目录里每一条用户可见的文案都必须有英文词条。
 * 漏一条，`pnpm test` 红——比一个需要人工想起来去跑的脚本可靠。
 */
import { describe, expect, it } from 'vitest';
import { catalog, setLocale, t } from '@podsec/i18n';
import { DEFAULT_RULES } from '@podsec/policy';
import { localizeThreat, THREAT_CATALOG } from './catalog.js';

/** 目录里所有会出现在界面/报表上的文案 */
function visibleStrings(): Array<{ id: string; text: string }> {
  const out: Array<{ id: string; text: string }> = [];
  for (const entry of THREAT_CATALOG) {
    out.push({ id: entry.id, text: entry.title });
    out.push({ id: entry.id, text: entry.summary });
    out.push({ id: entry.id, text: entry.remediation.action });
    out.push({ id: entry.id, text: entry.remediation.why });
    if (entry.gap) out.push({ id: entry.id, text: entry.gap });
    for (const control of entry.existingControls ?? []) out.push({ id: entry.id, text: control });
  }
  return out;
}

describe('威胁目录的英文词条', () => {
  it('每条用户可见文案都有英文，不存在悄悄回退中文的条目', () => {
    const en = catalog('en-US');
    const missing = visibleStrings()
      .filter((item) => !en[item.text])
      .map((item) => `${item.id}: ${item.text.slice(0, 50)}…`);
    expect(missing).toEqual([]);
  });

  it('目录里有大量非 ASCII 的中文条目（防止这条断言因为目录被清空而空转）', () => {
    expect(visibleStrings().length).toBeGreaterThan(90);
  });

  it('默认规则里会进入报表/拒绝理由的原因文案也有英文', () => {
    const en = catalog('en-US');
    // 这三组 why 都会出现在用户可见的输出里：guard 报表（hook）、
    // 网关拒绝理由与审计链 reason（toolMetadata / injection）。
    const reasons = [
      ...DEFAULT_RULES.hookRisk.riskPatterns.map((pattern) => pattern.why),
      ...DEFAULT_RULES.toolMetadata.suspiciousPatterns.map((pattern) => pattern.why),
      ...DEFAULT_RULES.injection.signals.map((signal) => signal.why),
    ];
    const missing = reasons
      .filter((why): why is string => Boolean(why))
      .filter((why) => !en[why]);
    expect(missing).toEqual([]);
  });
});

describe('渲染时本地化（不是模块加载时）', () => {
  const entry = THREAT_CATALOG[0]!;

  it('setLocale 之后拿到的标题是英文', () => {
    setLocale('en-US');
    try {
      const localized = localizeThreat(entry);
      expect(localized.title).toBe(t(entry.title));
      expect(localized.title).not.toMatch(/[\u4e00-\u9fff]/);
      expect(localized.remediation.action).not.toMatch(/[\u4e00-\u9fff]/);
    } finally {
      setLocale(null);
    }
  });

  it('切回中文后仍然是原样（英文词条不会污染中文输出）', () => {
    setLocale('zh-CN');
    try {
      expect(localizeThreat(entry).title).toBe(entry.title);
    } finally {
      setLocale(null);
    }
  });
});
