/**
 * 通用 Ed25519 detached 签名（对"规范序列化后的字符串"签名）。
 *
 * 抽成一层是因为有两个签名对象：策略（pod policy sign/verify）与规则包
 * （pod rules pack/verify）。两处如果各写一份 crypto 调用，迟早会出现
 * "策略能验签、规则包验不了"这种口径漂移的 bug——所以只留一份实现。
 *
 * 签名对象是 canonical 字符串而非原始文件字节：JSON 的空白与键顺序不应
 * 影响验签结果（同一条规则重排字段后仍应验签通过）。规范序列化由调用方
 * 提供（策略用 stableStringify(policy)，规则包用 canonicalRulePack）。
 */
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';

/** Ed25519 签名，返回 base64 */
export function signDetached(payload: string, privateKeyPem: string): string {
  return sign(null, Buffer.from(payload, 'utf8'), createPrivateKey(privateKeyPem)).toString('base64');
}

/** Ed25519 验签；任何错误（密钥格式错、签名长度错、base64 非法）都返回 false */
export function verifyDetached(payload: string, signatureBase64: string, publicKeyPem: string): boolean {
  try {
    return verify(
      null,
      Buffer.from(payload, 'utf8'),
      createPublicKey(publicKeyPem),
      Buffer.from(signatureBase64, 'base64'),
    );
  } catch {
    return false;
  }
}
