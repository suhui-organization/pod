/**
 * pod identity — Agent 的密码学身份、委托链与 JIT 令牌。
 *
 * 设计（docs/control-plane-hardening.md G11–G13）：
 * - 每个 agent 一对 ed25519 密钥，私钥 0600，落在 <root>/<agent>/；
 * - 委托链是"签名链接力"：每一跳由上一跳的 agent 签名，能力必须逐跳收窄；
 * - JIT 令牌是签名 + 有效期 + 作用域（server/tool/capability）+ 可单次消费；
 * - 本模块只做密码学与结构校验，"什么算越权"由调用方传规则（用户可编辑）。
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { t } from '@podsec/i18n';
import { stableStringify } from '@podsec/audit';

export const IDENTITY_ALGORITHM = 'ed25519';

export interface AgentIdentity {
  agent: string;
  algorithm: typeof IDENTITY_ALGORITHM;
  publicKeyPem: string;
  /** sha256(publicKeyPem) 前 16 位，用于人眼比对 */
  fingerprint: string;
  createdAt: string;
}

export function fingerprintOf(publicKeyPem: string): string {
  return createHash('sha256').update(publicKeyPem, 'utf8').digest('hex').slice(0, 16);
}

export function identityDir(root: string, agent: string): string {
  return join(root, sanitizeAgent(agent));
}

/**
 * agent 名会拼进路径，必须挡住 `../` 之类的越权写法。
 * 这里选择"直接拒绝"而不是静默转义：转义会让两个不同的 agent 名落到同一目录，
 * 身份就串了——宁可让调用方改名字。
 */
function sanitizeAgent(agent: string): string {
  const safe = agent.replace(/[^A-Za-z0-9._-]/g, '_');
  if (!safe || safe === '.' || safe === '..' || safe !== agent) {
    throw new Error(t('非法 agent 名: {agent}（只允许 A-Za-z0-9._-）', { agent }));
  }
  return safe;
}

function metaPath(root: string, agent: string): string {
  return join(identityDir(root, agent), 'identity.json');
}

function privateKeyPath(root: string, agent: string): string {
  return join(identityDir(root, agent), 'private.pem');
}

/** 生成（或覆盖）一个 agent 的身份；返回公开部分 */
export function generateAgentIdentity(agent: string, root: string, now: Date = new Date()): AgentIdentity {
  const { privateKey, publicKey } = generateKeyPairSync(IDENTITY_ALGORITHM);
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const dir = identityDir(root, agent);
  mkdirSync(dir, { recursive: true });
  const keyFile = privateKeyPath(root, agent);
  writeFileSync(keyFile, privateKeyPem, { encoding: 'utf8', mode: 0o600 });
  // 已存在的文件不会被 mode 改写，显式收紧权限
  chmodSync(keyFile, 0o600);
  const identity: AgentIdentity = {
    agent,
    algorithm: IDENTITY_ALGORITHM,
    publicKeyPem,
    fingerprint: fingerprintOf(publicKeyPem),
    createdAt: now.toISOString(),
  };
  writeFileSync(metaPath(root, agent), JSON.stringify(identity, null, 2) + '\n', 'utf8');
  return identity;
}

export function loadAgentIdentity(agent: string, root: string): AgentIdentity | null {
  const file = metaPath(root, agent);
  if (!existsSync(file)) return null;
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as AgentIdentity;
  } catch {
    return null;
  }
}

export function listAgentIdentities(root: string): AgentIdentity[] {
  if (!existsSync(root)) return [];
  const out: AgentIdentity[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const identity = loadAgentIdentity(entry.name, root);
    if (identity) out.push(identity);
  }
  return out.sort((a, b) => a.agent.localeCompare(b.agent));
}

/** 私钥是否仍然在盘上（身份"活着"的最低条件） */
export function hasPrivateKey(agent: string, root: string): boolean {
  return existsSync(privateKeyPath(root, agent));
}

export function signWithPem(privateKeyPem: string, payload: unknown): string {
  const key = createPrivateKey(privateKeyPem);
  return cryptoSign(null, Buffer.from(stableStringify(payload), 'utf8'), key).toString('base64');
}

/**
 * 去掉值为 undefined 的键再签名。
 * 原因：stableStringify 会把 `"k":undefined` 序列化成 `"k":null`，而 JSON.stringify
 * 落盘时直接丢键——不剔除的话，内存里验签能过、从文件读回来就过不了。
 */
function dropUndefined<T extends object>(value: T): T {
  const out = { ...value } as Record<string, unknown>;
  for (const key of Object.keys(out)) {
    if (out[key] === undefined) delete out[key];
  }
  return out as T;
}

export function verifyWithPem(publicKeyPem: string, payload: unknown, signatureB64: string): boolean {
  try {
    const key = createPublicKey(publicKeyPem);
    return cryptoVerify(
      null,
      Buffer.from(stableStringify(payload), 'utf8'),
      key,
      Buffer.from(signatureB64, 'base64'),
    );
  } catch {
    return false;
  }
}

/** 用某个 agent 的私钥签名；未初始化身份时抛错（fail-closed） */
export function signAsAgent(agent: string, root: string, payload: unknown): string {
  const file = privateKeyPath(root, agent);
  if (!existsSync(file)) {
    throw new Error(t('agent "{agent}" 没有私钥（先跑 pod identity init --agent {agent}）', { agent }));
  }
  return signWithPem(readFileSync(file, 'utf8'), payload);
}

/** 构造"按 agent 名取公钥"的解析器，供委托链/令牌校验用 */
export function publicKeyResolver(root: string): (agent: string) => string | null {
  return (agent: string) => loadAgentIdentity(agent, root)?.publicKeyPem ?? null;
}

// ---------- 委托链（G13） ----------

export interface DelegationLink {
  parent: string;
  child: string;
  capabilities: string[];
  issuedAt: string;
  expiresAt: string;
  signature: string;
}

export interface DelegationToken {
  v: 1;
  parent: string;
  child: string;
  capabilities: string[];
  issuedAt: string;
  expiresAt: string;
  /** 本跳的深度；根委托为 0 */
  depth: number;
  /** 祖先链（不含本跳），按时间顺序 */
  chain: DelegationLink[];
  signature: string;
}

export interface DelegationRules {
  maxDepth: number;
  requireSubset: boolean;
  /** 永不下放的敏感能力：可以自己持有，但不能委托给子 agent */
  forbiddenEscalation?: string[];
}

export interface DelegationVerifyResult {
  ok: boolean;
  errors: string[];
  /** 本跳实际生效的能力（逐跳交集） */
  capabilities: string[];
  depth: number;
  hops: string[];
}

type DelegationBody = Omit<DelegationToken, 'signature'>;

/**
 * 签名覆盖的是"这一跳"的五个字段，而不是外层 token 结构。
 * 理由：链路复用时（token.chain 里放的是同一个 link 对象），
 * 只有按 link 口径签名/验签才能逐环对上。
 * depth / chain 的完整性由结构校验保证（depth 必须等于 chain.length）。
 */
function linkBody(link: {
  parent: string;
  child: string;
  capabilities: string[];
  issuedAt: string;
  expiresAt: string;
}): {
  parent: string;
  child: string;
  capabilities: string[];
  issuedAt: string;
  expiresAt: string;
} {
  return {
    parent: link.parent,
    child: link.child,
    capabilities: link.capabilities,
    issuedAt: link.issuedAt,
    expiresAt: link.expiresAt,
  };
}

export interface IssueDelegationInput {
  parent: string;
  child: string;
  capabilities: string[];
  ttlSeconds: number;
  /** 父 agent 已有的祖先链；根委托留空 */
  chain?: DelegationLink[];
  now?: Date;
}

/** 由 parent 签发一跳委托；能力必须已收敛（越权检查在 verifyDelegation 里做） */
export function issueDelegation(input: IssueDelegationInput, signer: { agent: string; root: string }): DelegationToken {
  if (signer.agent !== input.parent) {
    throw new Error(t('委托必须由 parent 自己签名：parent={parent} signer={signer}', { parent: input.parent, signer: signer.agent }));
  }
  const now = input.now ?? new Date();
  const chain = input.chain ?? [];
  const link = dropUndefined({
    parent: input.parent,
    child: input.child,
    capabilities: [...input.capabilities].sort(),
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + input.ttlSeconds * 1000).toISOString(),
  });
  const body: DelegationBody = { v: 1, ...link, depth: chain.length, chain };
  return { ...body, signature: signAsAgent(signer.agent, signer.root, linkBody(link)) };
}

/** 把已签发的一跳转成链上的一环，便于再往下委托 */
export function linkOf(token: DelegationToken): DelegationLink {
  return {
    parent: token.parent,
    child: token.child,
    capabilities: token.capabilities,
    issuedAt: token.issuedAt,
    expiresAt: token.expiresAt,
    signature: token.signature,
  };
}

const subset = (child: string[], parent: string[]): string[] =>
  child.filter((c) => !parent.includes(c));

/**
 * 校验整条委托链：签名、有效期、深度、能力逐跳收窄、敏感能力不下放。
 * 任一环不成立即 ok=false（fail-closed），errors 给出可读原因。
 */
export function verifyDelegation(
  token: DelegationToken,
  opts: { rules: DelegationRules; resolvePublicKey: (agent: string) => string | null; now?: Date },
): DelegationVerifyResult {
  const now = opts.now ?? new Date();
  const errors: string[] = [];
  const hops: string[] = [];
  const forbidden = new Set(opts.rules.forbiddenEscalation ?? []);

  const parentKey = opts.resolvePublicKey(token.parent);
  if (!parentKey) errors.push(t('找不到 {agent} 的公钥', { agent: token.parent }));
  else if (!verifyWithPem(parentKey, linkBody(token), token.signature)) {
    errors.push(t('{parent} → {child} 的签名不成立', { parent: token.parent, child: token.child }));
  }

  if (token.depth !== token.chain.length) {
    errors.push(t('深度字段与实际链长不符：depth={depth} chain={chain}', { depth: token.depth, chain: token.chain.length }));
  }
  if (token.depth > opts.rules.maxDepth) {
    errors.push(t('委托深度 {depth} 超过上限 {max}', { depth: token.depth, max: opts.rules.maxDepth }));
  }
  if (new Date(token.expiresAt).getTime() <= now.getTime()) {
    errors.push(t('本跳委托已过期（{ts}）', { ts: token.expiresAt }));
  }

  // 祖先链：逐环验签，且时间上必须早于后继
  const links = [...token.chain, linkOf(token)];
  for (let i = 0; i < token.chain.length; i++) {
    const link = token.chain[i]!;
    const key = opts.resolvePublicKey(link.parent);
    if (!key) errors.push(t('找不到 {agent} 的公钥（链第 {i} 跳）', { agent: link.parent, i }));
    else if (!verifyWithPem(key, linkBody(link), link.signature)) {
      errors.push(t('{parent} → {child} 的签名不成立（链第 {i} 跳）', { parent: link.parent, child: link.child, i }));
    }
    if (new Date(link.expiresAt).getTime() <= now.getTime()) {
      errors.push(t('{parent} → {child} 已过期（链第 {i} 跳）', { parent: link.parent, child: link.child, i }));
    }
  }

  // 能力逐跳收窄
  let effective = links[0]!.capabilities;
  hops.push(`${links[0]!.parent} → ${links[0]!.child}`);
  for (let i = 1; i < links.length; i++) {
    const prev = links[i - 1]!;
    const cur = links[i]!;
    hops.push(`${cur.parent} → ${cur.child}`);
    if (opts.rules.requireSubset) {
      const escaped = subset(cur.capabilities, prev.capabilities);
      if (escaped.length > 0) {
        errors.push(
          t('{parent} → {child} 扩大了权限（父 {prevParent}→{prevChild} 没有：{escaped}）', {
            parent: cur.parent,
            child: cur.child,
            prevParent: prev.parent,
            prevChild: prev.child,
            escaped: escaped.join('、'),
          }),
        );
      }
    }
    effective = effective.filter((c) => cur.capabilities.includes(c));
  }

  if (forbidden.size > 0) {
    for (let i = 1; i < links.length; i++) {
      const link = links[i]!;
      const bad = link.capabilities.filter((c) => forbidden.has(c));
      if (bad.length > 0) {
        errors.push(
          t('{parent} → {child} 下放了不可委托的能力：{bad}', {
            parent: link.parent,
            child: link.child,
            bad: bad.join('、'),
          }),
        );
      }
    }
  }

  return { ok: errors.length === 0, errors, capabilities: effective, depth: token.depth, hops };
}

// ---------- JIT 令牌（G12） ----------

export interface GrantClaims {
  id: string;
  /** 被授权运行的 agent */
  agent: string;
  /** 作用域：server 名与工具名，空数组 = 不限 */
  servers?: string[];
  tools?: string[];
  capabilities?: string[];
  issuedAt: string;
  expiresAt: string;
  /** true = 只能消费一次 */
  singleUse: boolean;
  /** 签发者（用户的 root 身份或某个 agent） */
  issuedBy: string;
  reason?: string;
}

export interface Grant {
  v: 1;
  claims: GrantClaims;
  signature: string;
}

export function issueGrant(
  claims: Omit<GrantClaims, 'issuedAt' | 'expiresAt'> & { ttlSeconds: number; now?: Date },
  signer: { agent: string; root: string },
): Grant {
  const now = claims.now ?? new Date();
  const { ttlSeconds, now: _drop, ...rest } = claims;
  const body: GrantClaims = dropUndefined({
    ...rest,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlSeconds * 1000).toISOString(),
  });
  return { v: 1, claims: body, signature: signAsAgent(signer.agent, signer.root, body) };
}

export interface GrantVerifyResult {
  ok: boolean;
  errors: string[];
}

export function verifyGrant(
  grant: Grant,
  opts: { resolvePublicKey: (agent: string) => string | null; now?: Date; consumedAt?: string | null },
): GrantVerifyResult {
  const now = opts.now ?? new Date();
  const errors: string[] = [];
  const { signature: _sig, ...body } = grant;
  const key = opts.resolvePublicKey(grant.claims.issuedBy);
  if (!key) errors.push(t('找不到签发者 {issuer} 的公钥', { issuer: grant.claims.issuedBy }));
  else if (!verifyWithPem(key, body.claims, grant.signature)) errors.push(t('令牌签名不成立'));
  if (new Date(grant.claims.expiresAt).getTime() <= now.getTime()) {
    errors.push(t('令牌已过期（{ts}）', { ts: grant.claims.expiresAt }));
  }
  if (grant.claims.singleUse && opts.consumedAt) {
    errors.push(t('令牌是单次使用，已经在 {ts} 被消费', { ts: opts.consumedAt }));
  }
  return { ok: errors.length === 0, errors };
}

/** 令牌是否覆盖这次调用；空作用域 = 不限 */
export function grantCovers(
  claims: GrantClaims,
  call: { agent: string; server: string; tool: string; capabilities?: string[] },
): boolean {
  if (claims.agent !== call.agent) return false;
  if (claims.servers?.length && !claims.servers.includes(call.server)) return false;
  if (claims.tools?.length && !claims.tools.includes(call.tool)) return false;
  if (claims.capabilities?.length) {
    const have = call.capabilities ?? [];
    if (!claims.capabilities.some((c) => have.includes(c))) return false;
  }
  return true;
}

/** 令牌里写的是有效期而不是状态；消费状态落在同目录的 .consumed 标记上 */
export function grantConsumedPath(grantFile: string): string {
  return `${grantFile}.consumed`;
}

export function readConsumedAt(grantFile: string): string | null {
  const file = grantConsumedPath(grantFile);
  if (!existsSync(file)) return null;
  try {
    return readFileSync(file, 'utf8').trim();
  } catch {
    return null;
  }
}

export function markGrantConsumed(grantFile: string, at: Date = new Date()): void {
  writeFileSync(grantConsumedPath(grantFile), at.toISOString() + '\n', 'utf8');
}
