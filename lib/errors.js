/**
 * 校验器内部错误码与 RFC 6749 / RFC 7636 协议错误的映射。
 */

export const ErrorCode = Object.freeze({
  CODE_NOT_FOUND: 'code_not_found',
  CODE_CONSUMED: 'code_consumed',
  CODE_EXPIRED: 'code_expired',
  CLIENT_MISMATCH: 'client_mismatch',
  REDIRECT_URI_MISMATCH: 'redirect_uri_mismatch',
  USER_MISMATCH: 'user_mismatch',
  SESSION_MISMATCH: 'session_mismatch',
  PKCE_CHALLENGE_MISSING: 'pkce_challenge_missing',
  PKCE_VERIFIER_MISSING: 'pkce_verifier_missing',
  PKCE_VERIFIER_MALFORMED: 'pkce_verifier_malformed',
  PKCE_CHALLENGE_FAILED: 'pkce_challenge_failed',
  PKCE_METHOD_UNSUPPORTED: 'pkce_method_unsupported',
  NONCE_MISMATCH: 'nonce_mismatch',
  NONCE_REPLAYED: 'nonce_replayed'
});

/**
 * 内部错误码 -> OAuth 2.0 token 端点错误码。
 *
 * redirect_uri 校验失败按 RFC 7636 §4.6 映射为 invalid_request；
 * 其余绑定/兑换类失败按 RFC 6749 §5.2 映射为 invalid_grant。
 */
const OAUTH_ERROR = Object.freeze({
  [ErrorCode.CODE_NOT_FOUND]: 'invalid_grant',
  [ErrorCode.CODE_CONSUMED]: 'invalid_grant',
  [ErrorCode.CODE_EXPIRED]: 'invalid_grant',
  [ErrorCode.CLIENT_MISMATCH]: 'invalid_grant',
  [ErrorCode.REDIRECT_URI_MISMATCH]: 'invalid_request',
  [ErrorCode.USER_MISMATCH]: 'invalid_grant',
  [ErrorCode.SESSION_MISMATCH]: 'invalid_grant',
  [ErrorCode.PKCE_CHALLENGE_MISSING]: 'invalid_request',
  [ErrorCode.PKCE_VERIFIER_MISSING]: 'invalid_request',
  [ErrorCode.PKCE_VERIFIER_MALFORMED]: 'invalid_grant',
  [ErrorCode.PKCE_CHALLENGE_FAILED]: 'invalid_grant',
  [ErrorCode.PKCE_METHOD_UNSUPPORTED]: 'invalid_grant',
  [ErrorCode.NONCE_MISMATCH]: 'invalid_grant',
  [ErrorCode.NONCE_REPLAYED]: 'invalid_grant'
});

const ERROR_DESCRIPTION = Object.freeze({
  [ErrorCode.CODE_NOT_FOUND]: '授权码不存在',
  [ErrorCode.CODE_CONSUMED]: '授权码已被消费，重复兑换被拒绝',
  [ErrorCode.CODE_EXPIRED]: '授权码已过期',
  [ErrorCode.CLIENT_MISMATCH]: '授权码与当前 client_id 不匹配',
  [ErrorCode.REDIRECT_URI_MISMATCH]: 'redirect_uri 与授权请求时登记的值不匹配',
  [ErrorCode.USER_MISMATCH]: '授权码与当前用户不匹配',
  [ErrorCode.SESSION_MISMATCH]: '授权码与当前用户会话不匹配',
  [ErrorCode.PKCE_CHALLENGE_MISSING]: '授权请求缺少 code_challenge，PKCE 为强制项',
  [ErrorCode.PKCE_VERIFIER_MISSING]: '启用了 PKCE 但未提供 code_verifier',
  [ErrorCode.PKCE_VERIFIER_MALFORMED]: 'code_verifier 格式不符合 RFC 7636',
  [ErrorCode.PKCE_CHALLENGE_FAILED]: 'code_verifier 与 code_challenge 不匹配',
  [ErrorCode.PKCE_METHOD_UNSUPPORTED]: '仅支持 S256 code_challenge_method',
  [ErrorCode.NONCE_MISMATCH]: 'nonce 与授权请求时登记的值不匹配',
  [ErrorCode.NONCE_REPLAYED]: 'nonce 已在之前的兑换中使用过'
});

export class ValidationError extends Error {
  constructor(code) {
    super(ERROR_DESCRIPTION[code] ?? code);
    this.name = 'ValidationError';
    this.code = code;
    this.oauthError = OAUTH_ERROR[code] ?? 'invalid_grant';
  }
}

export function toOAuthErrorBody(code) {
  return {
    error: OAUTH_ERROR[code] ?? 'invalid_grant',
    error_description: ERROR_DESCRIPTION[code] ?? code
  };
}
