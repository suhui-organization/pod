import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { stableStringify } from '@podsec/audit';
import type { Policy } from '@podsec/policy';

/** 策略的规范序列化：键排序，保证签名与验签口径一致 */
export function canonicalPolicy(policy: Policy): string {
  return stableStringify(policy);
}

/** Ed25519 签名（detached，base64） */
export function signPolicy(policy: Policy, privateKeyPem: string): string {
  const signature = sign(null, Buffer.from(canonicalPolicy(policy), 'utf8'), createPrivateKey(privateKeyPem));
  return signature.toString('base64');
}

/** Ed25519 验签；任何错误都返回 false */
export function verifyPolicy(policy: Policy, signatureBase64: string, publicKeyPem: string): boolean {
  try {
    return verify(
      null,
      Buffer.from(canonicalPolicy(policy), 'utf8'),
      createPublicKey(publicKeyPem),
      Buffer.from(signatureBase64, 'base64'),
    );
  } catch {
    return false;
  }
}
