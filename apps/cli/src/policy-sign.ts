import { stableStringify } from '@podsec/audit';
import { signDetached, verifyDetached, type Policy } from '@podsec/policy';

// 签名实现收敛在 @podsec/policy 的 sign.ts（策略与规则包共用同一口径）。
// 这里只保留"策略"这一层语义：规范序列化 + 委托签名。

/** 策略的规范序列化：键排序，保证签名与验签口径一致 */
export function canonicalPolicy(policy: Policy): string {
  return stableStringify(policy);
}

/** Ed25519 签名（detached，base64） */
export function signPolicy(policy: Policy, privateKeyPem: string): string {
  return signDetached(canonicalPolicy(policy), privateKeyPem);
}

/** Ed25519 验签；任何错误都返回 false */
export function verifyPolicy(policy: Policy, signatureBase64: string, publicKeyPem: string): boolean {
  return verifyDetached(canonicalPolicy(policy), signatureBase64, publicKeyPem);
}
