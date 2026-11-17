import { verifyPkce } from './pkce.js';
import { ErrorCode } from './errors.js';

/**
 * redirect URI 必须逐字符精确匹配（RFC 6749 §4.1.3），
 * 不允许仅 host/path 相同而 query 参数不同。
 */
export function redirectUriMatches(storedRedirectUri, requestedRedirectUri) {
  return (
    typeof requestedRedirectUri === 'string' &&
    storedRedirectUri === requestedRedirectUri
  );
}

/**
 * 授权码绑定校验（纯函数，无副作用，时钟由调用方注入）。
 *
 * @param {object} record 授权阶段持久化的授权码记录
 * @param {object} request 兑换请求
 * @param {number} now 当前时间（epoch 毫秒）
 * @returns {{ ok: true } | { ok: false, code: string }}
 */
export function validateBinding(record, request, now) {
  const fail = (code) => ({ ok: false, code });

  if (record.consumed) {
    return fail(ErrorCode.CODE_CONSUMED);
  }

  if (now >= record.expiresAt) {
    return fail(ErrorCode.CODE_EXPIRED);
  }

  if (request.clientId !== record.clientId) {
    return fail(ErrorCode.CLIENT_MISMATCH);
  }

  if (!redirectUriMatches(record.redirectUri, request.redirectUri)) {
    return fail(ErrorCode.REDIRECT_URI_MISMATCH);
  }

  if (request.user?.subject !== record.user.subject) {
    return fail(ErrorCode.USER_MISMATCH);
  }

  if (request.user?.sessionId !== record.user.sessionId) {
    return fail(ErrorCode.SESSION_MISMATCH);
  }

  const pkceError = verifyPkce({
    codeChallenge: record.codeChallenge,
    codeChallengeMethod: record.codeChallengeMethod,
    codeVerifier: request.codeVerifier
  });
  if (pkceError) {
    return fail(pkceError);
  }

  if (request.nonce !== record.nonce) {
    return fail(ErrorCode.NONCE_MISMATCH);
  }

  return { ok: true };
}
