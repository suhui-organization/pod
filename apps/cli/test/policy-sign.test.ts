import { describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Policy } from '@podsec/policy';
import { canonicalPolicy, signPolicy, verifyPolicy } from '../src/policy-sign.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '../src/index.ts');

const policy: Policy = {
  version: '0.1.0',
  agent: 'a',
  defaultDecision: 'deny',
  servers: { s: { allow: ['read_file'] } },
  capabilityRules: { deny: ['external-communication'] },
};

describe('policy signing', () => {
  it('signs and verifies a policy', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const signature = signPolicy(policy, privatePem);
    expect(verifyPolicy(policy, signature, publicPem)).toBe(true);
  });

  it('rejects a tampered policy', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const signature = signPolicy(policy, privatePem);
    const tampered: Policy = { ...policy, capabilityRules: { deny: [] } };
    expect(verifyPolicy(tampered, signature, publicPem)).toBe(false);
  });

  it('canonicalizes key order', () => {
    expect(canonicalPolicy({ ...policy, agent: 'a' })).toBe(canonicalPolicy(policy));
  });

  it('CLI sign + verify round-trip, and fails on tamper', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-policy-sign-'));
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const privatePem = join(dir, 'private.pem');
    const publicPem = join(dir, 'public.pem');
    writeFileSync(privatePem, privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), 'utf8');
    writeFileSync(publicPem, publicKey.export({ type: 'spki', format: 'pem' }).toString(), 'utf8');
    const policyPath = join(dir, 'policy.json');
    const sigPath = join(dir, 'policy.sig');
    writeFileSync(policyPath, JSON.stringify(policy), 'utf8');

    const sign = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'policy', 'sign', '--key', privatePem, '--in', policyPath, '--out', sigPath],
      { encoding: 'utf8' },
    );
    expect(sign.status).toBe(0);
    const verify = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'policy', 'verify', '--key', publicPem, '--in', policyPath, '--sig', sigPath],
      { encoding: 'utf8' },
    );
    expect(verify.status).toBe(0);

    writeFileSync(policyPath, JSON.stringify({ ...policy, capabilityRules: { deny: [] } }), 'utf8');
    const tampered = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'policy', 'verify', '--key', publicPem, '--in', policyPath, '--sig', sigPath],
      { encoding: 'utf8' },
    );
    expect(tampered.status).toBe(1);
  });
});
