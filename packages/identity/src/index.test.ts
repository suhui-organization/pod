import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  generateAgentIdentity,
  grantCovers,
  issueDelegation,
  issueGrant,
  linkOf,
  listAgentIdentities,
  loadAgentIdentity,
  markGrantConsumed,
  publicKeyResolver,
  readConsumedAt,
  signAsAgent,
  verifyDelegation,
  verifyGrant,
  verifyWithPem,
} from './index.js';

let root: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'pod-identity-'));
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('agent identity', () => {
  it('生成 ed25519 身份，私钥 0600，指纹可复算', () => {
    const id = generateAgentIdentity('planner', root);
    expect(id.algorithm).toBe('ed25519');
    expect(id.fingerprint).toHaveLength(16);
    expect(loadAgentIdentity('planner', root)).toEqual(id);
    // 私钥不能是 world-readable
    const mode = statSync(join(root, 'planner', 'private.pem')).mode & 0o777;
    expect(mode & 0o077).toBe(0);
  });

  it('签名可验证，载荷被改动后验证失败', () => {
    const id = generateAgentIdentity('planner', root);
    const sig = signAsAgent('planner', root, { a: 1, b: [2, 3] });
    expect(verifyWithPem(id.publicKeyPem, { b: [2, 3], a: 1 }, sig)).toBe(true);
    expect(verifyWithPem(id.publicKeyPem, { a: 2 }, sig)).toBe(false);
    expect(verifyWithPem(id.publicKeyPem, { a: 1, b: [2, 4] }, sig)).toBe(false);
  });

  it('未初始化身份的 agent 不能签名（fail-closed），并且 list 只返回已建身份', () => {
    generateAgentIdentity('planner', root);
    expect(() => signAsAgent('ghost', root, {})).toThrow(/没有私钥/);
    expect(listAgentIdentities(root).map((i) => i.agent)).toEqual(['planner']);
  });

  it('拒绝把 ../ 之类写进 agent 名（路径逃逸）', () => {
    expect(() => generateAgentIdentity('../../etc/passwd', root)).toThrow(/非法 agent 名/);
  });
});

describe('delegation chain', () => {
  const rules = { maxDepth: 2, requireSubset: true, forbiddenEscalation: ['exec'] };

  beforeEach(() => {
    for (const agent of ['orchestrator', 'worker', 'sub']) generateAgentIdentity(agent, root);
  });

  it('多跳委托逐跳收窄时通过，并算出实际生效能力', () => {
    const hop1 = issueDelegation(
      { parent: 'orchestrator', child: 'worker', capabilities: ['read-private-data', 'exec'], ttlSeconds: 3600 },
      { agent: 'orchestrator', root },
    );
    const hop2 = issueDelegation(
      {
        parent: 'worker',
        child: 'sub',
        capabilities: ['read-private-data'],
        ttlSeconds: 600,
        chain: [linkOf(hop1)],
      },
      { agent: 'worker', root },
    );
    const result = verifyDelegation(hop2, { rules, resolvePublicKey: publicKeyResolver(root) });
    expect(result.ok).toBe(true);
    expect(result.capabilities).toEqual(['read-private-data']);
    expect(result.depth).toBe(1);
    expect(result.hops).toEqual(['orchestrator → worker', 'worker → sub']);
  });

  it('子 agent 扩大权限时被拒（链式收窄）', () => {
    const hop1 = issueDelegation(
      { parent: 'orchestrator', child: 'worker', capabilities: ['read-private-data'], ttlSeconds: 3600 },
      { agent: 'orchestrator', root },
    );
    const hop2 = issueDelegation(
      {
        parent: 'worker',
        child: 'sub',
        capabilities: ['read-private-data', 'destructive-write'],
        ttlSeconds: 600,
        chain: [linkOf(hop1)],
      },
      { agent: 'worker', root },
    );
    const result = verifyDelegation(hop2, { rules, resolvePublicKey: publicKeyResolver(root) });
    expect(result.ok).toBe(false);
    expect(result.errors.join(' ')).toMatch(/扩大了权限.*destructive-write/);
  });

  it('敏感能力不可下放（forbiddenEscalation）', () => {
    const hop1 = issueDelegation(
      { parent: 'orchestrator', child: 'worker', capabilities: ['exec'], ttlSeconds: 3600 },
      { agent: 'orchestrator', root },
    );
    const hop2 = issueDelegation(
      { parent: 'worker', child: 'sub', capabilities: ['exec'], ttlSeconds: 600, chain: [linkOf(hop1)] },
      { agent: 'worker', root },
    );
    const result = verifyDelegation(hop2, { rules, resolvePublicKey: publicKeyResolver(root) });
    expect(result.ok).toBe(false);
    expect(result.errors.join(' ')).toMatch(/不可委托的能力.*exec/);
  });

  it('超过 maxDepth / 过期 / 冒充 parent 签名都会失败', () => {
    const deep = issueDelegation(
      { parent: 'orchestrator', child: 'worker', capabilities: [], ttlSeconds: 3600 },
      { agent: 'orchestrator', root },
    );
    const overDepth = {
      ...deep,
      depth: 3,
      chain: [linkOf(deep), linkOf(deep), linkOf(deep)],
    };
    const depthResult = verifyDelegation(overDepth, { rules, resolvePublicKey: publicKeyResolver(root) });
    expect(depthResult.ok).toBe(false);
    expect(depthResult.errors.join(' ')).toMatch(/深度 3 超过上限 2/);

    const expired = issueDelegation(
      { parent: 'orchestrator', child: 'worker', capabilities: [], ttlSeconds: 60, now: new Date('2020-01-01T00:00:00Z') },
      { agent: 'orchestrator', root },
    );
    const expiredResult = verifyDelegation(expired, { rules, resolvePublicKey: publicKeyResolver(root) });
    expect(expiredResult.ok).toBe(false);
    expect(expiredResult.errors.join(' ')).toMatch(/已过期/);

    expect(() =>
      issueDelegation({ parent: 'orchestrator', child: 'worker', capabilities: [], ttlSeconds: 60 }, { agent: 'worker', root }),
    ).toThrow(/必须由 parent 自己签名/);
  });

  it('找不到公钥时不放行（未知 agent 不能凭自述通过）', () => {
    const token = issueDelegation(
      { parent: 'orchestrator', child: 'worker', capabilities: [], ttlSeconds: 60 },
      { agent: 'orchestrator', root },
    );
    const result = verifyDelegation(token, {
      rules,
      resolvePublicKey: (agent) => (agent === 'orchestrator' ? null : publicKeyResolver(root)(agent)),
    });
    expect(result.ok).toBe(false);
    expect(result.errors.join(' ')).toMatch(/找不到 orchestrator 的公钥/);
  });
});

describe('JIT grant', () => {
  beforeEach(() => {
    generateAgentIdentity('root-user', root);
    generateAgentIdentity('worker', root);
  });

  it('签发的令牌可验证，且只在作用域内生效', () => {
    const grant = issueGrant(
      {
        id: 'g1',
        agent: 'worker',
        servers: ['filesystem'],
        tools: ['write_file'],
        singleUse: true,
        issuedBy: 'root-user',
        ttlSeconds: 900,
      },
      { agent: 'root-user', root },
    );
    expect(verifyGrant(grant, { resolvePublicKey: publicKeyResolver(root) }).ok).toBe(true);
    expect(grantCovers(grant.claims, { agent: 'worker', server: 'filesystem', tool: 'write_file' })).toBe(true);
    expect(grantCovers(grant.claims, { agent: 'worker', server: 'github', tool: 'write_file' })).toBe(false);
    expect(grantCovers(grant.claims, { agent: 'worker', server: 'filesystem', tool: 'delete_file' })).toBe(false);
    expect(grantCovers(grant.claims, { agent: 'other', server: 'filesystem', tool: 'write_file' })).toBe(false);
  });

  it('过期令牌无效；单次令牌消费后失效', () => {
    const expired = issueGrant(
      { id: 'g2', agent: 'worker', singleUse: false, issuedBy: 'root-user', ttlSeconds: 60, now: new Date('2020-01-01T00:00:00Z') },
      { agent: 'root-user', root },
    );
    expect(verifyGrant(expired, { resolvePublicKey: publicKeyResolver(root) }).errors.join(' ')).toMatch(/已过期/);

    const file = join(root, 'g3.json');
    const grant = issueGrant(
      { id: 'g3', agent: 'worker', singleUse: true, issuedBy: 'root-user', ttlSeconds: 600 },
      { agent: 'root-user', root },
    );
    expect(readConsumedAt(file)).toBeNull();
    markGrantConsumed(file, new Date('2026-01-01T00:00:00Z'));
    const consumed = verifyGrant(grant, {
      resolvePublicKey: publicKeyResolver(root),
      consumedAt: readConsumedAt(file),
    });
    expect(consumed.ok).toBe(false);
    expect(consumed.errors.join(' ')).toMatch(/单次使用/);
  });

  it('篡改作用域后签名失效', () => {
    const grant = issueGrant(
      { id: 'g4', agent: 'worker', tools: ['read_file'], singleUse: false, issuedBy: 'root-user', ttlSeconds: 600 },
      { agent: 'root-user', root },
    );
    const tampered = { ...grant, claims: { ...grant.claims, tools: ['read_file', 'delete_file'] } };
    expect(verifyGrant(tampered, { resolvePublicKey: publicKeyResolver(root) }).ok).toBe(false);
  });

  it('可选字段缺省时，落盘再读回仍然验签通过（undefined 不能进签名正文）', () => {
    const grant = issueGrant(
      {
        id: 'g5',
        agent: 'worker',
        issuedBy: 'root-user',
        ttlSeconds: 600,
        singleUse: false,
        servers: undefined,
        tools: undefined,
        capabilities: undefined,
        reason: undefined,
      },
      { agent: 'root-user', root },
    );
    const roundTripped = JSON.parse(JSON.stringify(grant)) as typeof grant;
    const result = verifyGrant(roundTripped, { resolvePublicKey: publicKeyResolver(root) });
    expect(result.errors).toEqual([]);
    expect(result.ok).toBe(true);
  });
});
