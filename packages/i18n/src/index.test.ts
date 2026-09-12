import { describe, expect, it } from 'vitest';
import { catalog, getLocale, normalizeLocale, resolveLocale, setLocale, t, translate } from './index.js';

describe('语言解析', () => {
  it('归一化各种写法', () => {
    expect(normalizeLocale('en')).toBe('en-US');
    expect(normalizeLocale('en_US.UTF-8')).toBe('en-US');
    expect(normalizeLocale('zh_CN')).toBe('zh-CN');
    expect(normalizeLocale('fr_FR')).toBeNull();
    expect(normalizeLocale(undefined)).toBeNull();
  });

  it('优先级：POD_LANG > LC_ALL > LANG > 默认中文', () => {
    expect(resolveLocale({ POD_LANG: 'en-US' })).toBe('en-US');
    expect(resolveLocale({ LC_ALL: 'zh_CN.UTF-8' })).toBe('zh-CN');
    expect(resolveLocale({ LANG: 'en_US.UTF-8' })).toBe('en-US');
    expect(resolveLocale({})).toBe('zh-CN');
    // POD_LANG 覆盖其它
    expect(resolveLocale({ POD_LANG: 'zh-CN', LANG: 'en_US.UTF-8' })).toBe('zh-CN');
  });
});

describe('取词', () => {
  it('未翻译的字符串原样返回（不会变成 key 名或空白）', () => {
    setLocale('en-US');
    expect(t('这条还没有翻译')).toBe('这条还没有翻译');
    setLocale('zh-CN');
    expect(t('已写入')).toBe('已写入');
  });

  it('占位符按名替换；缺变量时保留原样而不是抛错', () => {
    setLocale('en-US');
    expect(t('草稿已写入: {path}', { path: '/tmp/a.json' })).toBe('Draft written: /tmp/a.json');
    // 占位符没给值时保留原样，不让格式化失败再制造一个错误
    expect(t('草稿已写入: {path}')).toBe('Draft written: {path}');
  });

  it('translate() 指定语言，不影响当前语言', () => {
    setLocale('zh-CN');
    expect(translate('已写入', 'en-US')).toBe('Wrote');
    expect(getLocale()).toBe('zh-CN');
  });

  it('英文词表非空（防止误清空词表导致"英文模式全中文"）', () => {
    expect(Object.keys(catalog('en-US')).length).toBeGreaterThan(50);
  });
});
