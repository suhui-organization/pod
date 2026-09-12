/**
 * 规则包测试：签名口径、schema 校验、放宽守卫。
 *
 * 放宽守卫是这批逻辑里最要紧的一条——"更新"本身可以是一次攻击：
 * 让订阅者以为在升级，实际把 deny 列表清空。所以这里对"静默削弱"
 * 的每种路径各留一个用例。
 */
import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { DEFAULT_RULES } from './rules.js';
import {
  applyRulePack,
  buildRulePack,
  canonicalRulePack,
  detectRelaxations,
  diffRules,
  parseRulePack,
  RulePackError,
  signRulePack,
  verifyRulePack,
  type RulePack,
  type SignedRulePack,
} from './rules-pack.js';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const PRIVATE_PEM = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const PUBLIC_PEM = publicKey.export({ type: 'spki', format: 'pem' }).toString();

/** DEFAULT_RULES 是模块级单例、数组是共享引用——测试一律用克隆，避免互相污染 */
function baseRules() {
  return structuredClone(DEFAULT_RULES);
}

/** 注入信号现在带置信级别；这里给个最短构造器 */
const sig = (text: string, severity: 'high' | 'medium' | 'low' = 'high') => ({
  id: `t-${text}`,
  text,
  severity,
});

function packOf(rules: unknown, meta: { packVersion?: string; issuedBy?: string } = {}) {
  return buildRulePack(rules as never, {
    packVersion: meta.packVersion ?? '2026.09.12',
    issuedBy: meta.issuedBy ?? 'podsec',
    issuedAt: '2026-09-12T00:00:00.000Z',
  });
}

describe('签名与解析', () => {
  it('签名后可以验签，内容被改则验签失败', () => {
    const pack = packOf({ injection: { signals: [sig('ignore previous'), sig('新注入词')] } });
    const signed = signRulePack(pack, PRIVATE_PEM);
    expect(verifyRulePack(signed, PUBLIC_PEM)).toBe(true);

    // 攻击场景：签发之后往包里塞一条放宽规则
    const tampered: SignedRulePack = { ...signed, rules: { injection: { signals: [] } } };
    expect(verifyRulePack(tampered, PUBLIC_PEM)).toBe(false);
  });

  it('无签名的包验签为 false（而不是抛错）', () => {
    expect(verifyRulePack(packOf({}), PUBLIC_PEM)).toBe(false);
  });

  it('规范序列化与键顺序无关：重排字段后签名仍然有效', () => {
    const signed = signRulePack(packOf({ injection: { signals: [sig('a'), sig('b')] } }), PRIVATE_PEM);
    const reordered = {
      rules: signed.rules,
      issuedAt: signed.issuedAt,
      issuedBy: signed.issuedBy,
      packVersion: signed.packVersion,
      schema: signed.schema,
      signature: signed.signature,
    } as SignedRulePack;
    expect(canonicalRulePack(reordered)).toBe(canonicalRulePack(signed));
    expect(verifyRulePack(reordered, PUBLIC_PEM)).toBe(true);
  });

  it('schema / 必填字段缺失一律抛错（fail-closed）', () => {
    expect(() => parseRulePack('not json')).toThrow(RulePackError);
    expect(() => parseRulePack(JSON.stringify({ schema: 'other/v1' }))).toThrow(/schema/);
    expect(() =>
      parseRulePack(JSON.stringify({ schema: 'pod-rules-pack/v1', issuedBy: 'x', issuedAt: 'y', rules: {} })),
    ).toThrow(/packVersion/);
    expect(() =>
      parseRulePack(JSON.stringify({ schema: 'pod-rules-pack/v1', packVersion: '1', issuedAt: 'y', rules: {} })),
    ).toThrow(/issuedBy/);
    expect(() =>
      parseRulePack(JSON.stringify({ schema: 'pod-rules-pack/v1', packVersion: '1', issuedBy: 'x', rules: {} })),
    ).toThrow(/issuedAt/);
  });

  it('签名包能被解析回等价对象', () => {
    const signed = signRulePack(packOf({ injection: { signals: [sig('x')] } }), PRIVATE_PEM);
    const parsed = parseRulePack(JSON.stringify(signed, null, 2));
    expect(verifyRulePack(parsed, PUBLIC_PEM)).toBe(true);
  });
});

describe('放宽守卫', () => {
  it('纯收紧的包直接应用', () => {
    const base = baseRules();
    const pack = packOf({ injection: { signals: [...base.injection.signals, sig('exfiltrate to')] } });
    const { rules, relaxations } = applyRulePack(base, pack);
    expect(relaxations).toEqual([]);
    expect(rules.injection.signals.map((s) => s.text)).toContain('exfiltrate to');
  });

  it('包替换掉用户自己加的模式 → 拒绝应用', () => {
    const base = baseRules();
    base.injection.signals = [...base.injection.signals, sig('我们内部的告警暗号')];
    // 订阅包只带自己那张表，数组整体替换 → 用户那条被挤掉
    const pack = packOf({ injection: { signals: [sig('ignore previous')] } });
    expect(() => applyRulePack(base, pack)).toThrow(/放宽/);
    const { rules } = applyRulePack(base, pack, { allowRelax: true });
    expect(rules.injection.signals.map((s) => s.text)).toEqual(['ignore previous']);
  });

  it('把 severity 从 high 降成 low → 判为放宽', () => {
    const base = baseRules();
    const downgraded = base.hookRisk.riskPatterns.map((p) =>
      p.id === 'net-egress' ? { ...p, severity: 'low' as const } : p,
    );
    const pack = packOf({ hookRisk: { riskPatterns: downgraded } });
    expect(() => applyRulePack(base, pack)).toThrow(/放宽/);
    const applied = applyRulePack(base, pack, { allowRelax: true });
    expect(applied.relaxations.some((r) => r.where.includes('net-egress'))).toBe(true);
  });

  it('把布尔检查从 true 关成 false → 判为放宽', () => {
    const base = baseRules();
    expect(base.packages.requireVersionPin).toBe(true);
    const pack = packOf({ packages: { requireVersionPin: false } });
    expect(() => applyRulePack(base, pack)).toThrow(/放宽/);
  });

  it('只加路径、不改布尔 → 不算放宽', () => {
    const base = baseRules();
    const pack = packOf({ freeze: { paths: [...base.freeze.paths, '~/.newagent/config.json'] } });
    expect(applyRulePack(base, pack).relaxations).toEqual([]);
  });

  it('合并后不合法的包（坏正则）被拒绝，而不是静默落盘', () => {
    const bad = {
      ...packOf({}),
      rules: { hookRisk: { riskPatterns: [{ id: 'x', re: '([', severity: 'high' }] } },
    } as unknown as RulePack;
    expect(() => applyRulePack(baseRules(), bad, { allowRelax: true })).toThrow(RulePackError);
  });

  it('把整个子对象置为 null 时抛 RulePackError 而不是 TypeError', () => {
    const bad = { ...packOf({}), rules: { hookRisk: null } } as unknown as RulePack;
    expect(() => applyRulePack(baseRules(), bad, { allowRelax: true })).toThrow(RulePackError);
  });

  it('数值阈值变化标为 unknown——不猜方向，交给人看', () => {
    const base = baseRules();
    const changes = diffRules(base, { ...base, auditHealth: { ...base.auditHealth, maxIdleHours: 999 } });
    const change = changes.find((c) => c.where.endsWith('maxIdleHours'));
    expect(change?.impact).toBe('unknown');
    expect(detectRelaxations(changes)).toEqual([]);
  });
});

describe('收紧守卫（放宽守卫的反方向）', () => {
  it('会匹配一切的过短信号被拒绝——"e" 这种子串是笔误，不是安全策略', () => {
    const base = baseRules();
    const pack = packOf({ injection: { signals: [...base.injection.signals, sig('e')] } });
    expect(() => applyRulePack(base, pack)).toThrow(/过短信号/);
    expect(() => applyRulePack(base, pack, { allowExpansion: true })).not.toThrow();
  });

  it('一次新增的阻断级信号超过预算时被拒（让单次推送的影响面可控）', () => {
    const base = baseRules();
    const many = Array.from({ length: 6 }, (_, i) => sig(`新增信号-${i}`));
    const pack = packOf({ injection: { signals: [...base.injection.signals, ...many] } });
    expect(() => applyRulePack(base, pack)).toThrow(/超过本次上限/);
    expect(applyRulePack(base, pack, { allowExpansion: true }).rules.injection.signals).toHaveLength(
      base.injection.signals.length + 6,
    );
  });

  it('正常的少量更新不受影响（守卫不能把订阅价值一起拦掉）', () => {
    const base = baseRules();
    const pack = packOf({
      injection: { signals: [...base.injection.signals, sig('一条新注入词'), sig('另一条新注入词')] },
    });
    expect(applyRulePack(base, pack).relaxations).toEqual([]);
  });

  it('中低置信新增不占阻断预算（它们本来就不拦东西）', () => {
    const base = baseRules();
    const many = Array.from({ length: 10 }, (_, i) => sig(`低置信-${i}`, 'low'));
    const pack = packOf({ injection: { signals: [...base.injection.signals, ...many] } });
    expect(() => applyRulePack(base, pack)).not.toThrow();
  });
});
