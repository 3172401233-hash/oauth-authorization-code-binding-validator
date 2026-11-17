import { createHash, timingSafeEqual } from 'node:crypto';

/**
 * RFC 7636 §4.1：code_verifier 为 43~128 个 unreserved 字符。
 */
const VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;

/**
 * 计算 S256 code_challenge：BASE64URL(SHA256(code_verifier))。
 */
export function computeS256Challenge(codeVerifier) {
  return createHash('sha256').update(codeVerifier).digest('base64url');
}

export function isValidVerifierFormat(codeVerifier) {
  return typeof codeVerifier === 'string' && VERIFIER_RE.test(codeVerifier);
}

/**
 * 以常量时间比较两个 base64url 字符串，避免挑战值计时侧信道。
 */
function safeEqual(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

/**
 * 校验 PKCE。授权码流程强制启用 PKCE，且仅支持 S256。
 *
 * @returns {string|undefined} 失败时返回内部错误码，通过时返回 undefined
 */
export function verifyPkce({ codeChallenge, codeChallengeMethod, codeVerifier }) {
  if (codeChallengeMethod !== 'S256') {
    return 'pkce_method_unsupported';
  }
  if (codeVerifier === undefined || codeVerifier === null || codeVerifier === '') {
    return 'pkce_verifier_missing';
  }
  if (!isValidVerifierFormat(codeVerifier)) {
    return 'pkce_verifier_malformed';
  }
  const computed = computeS256Challenge(codeVerifier);
  if (!safeEqual(computed, String(codeChallenge))) {
    return 'pkce_challenge_failed';
  }
  return undefined;
}
