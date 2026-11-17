import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateBinding, redirectUriMatches } from '../lib/validator.js';
import { computeS256Challenge } from '../lib/pkce.js';
import { ErrorCode } from '../lib/errors.js';

const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const T0 = 1_700_000_000_000;

function record(overrides = {}) {
  return {
    clientId: 'client-a',
    redirectUri: 'https://app.example.com/cb',
    codeChallenge: computeS256Challenge(VERIFIER),
    codeChallengeMethod: 'S256',
    nonce: 'n1',
    user: { subject: 'user-1', sessionId: 'session-1' },
    expiresAt: T0 + 60_000,
    consumed: false,
    ...overrides
  };
}

function request(overrides = {}) {
  return {
    clientId: 'client-a',
    redirectUri: 'https://app.example.com/cb',
    codeVerifier: VERIFIER,
    nonce: 'n1',
    user: { subject: 'user-1', sessionId: 'session-1' },
    ...overrides
  };
}

test('完整匹配时校验通过', () => {
  assert.deepEqual(validateBinding(record(), request(), T0), { ok: true });
});

test('redirectUriMatches 为逐字符精确比较', () => {
  const uri = 'https://app.example.com/cb?a=1';
  assert.equal(redirectUriMatches(uri, uri), true);
  assert.equal(redirectUriMatches(uri, 'https://app.example.com/cb?a=2'), false);
  assert.equal(redirectUriMatches(uri, 'https://app.example.com/cb'), false);
  assert.equal(redirectUriMatches(uri, undefined), false);
});

test('已消费的授权码即使同时过期也优先报 code_consumed', () => {
  const result = validateBinding(
    record({ consumed: true, expiresAt: T0 - 1 }),
    request(),
    T0
  );
  assert.deepEqual(result, { ok: false, code: ErrorCode.CODE_CONSUMED });
});

test('各绑定字段独立返回对应错误码', () => {
  const cases = [
    [{ clientId: 'client-x' }, ErrorCode.CLIENT_MISMATCH],
    [{ redirectUri: 'https://app.example.com/cb?x=1' }, ErrorCode.REDIRECT_URI_MISMATCH],
    [{ user: { subject: 'user-2', sessionId: 'session-1' } }, ErrorCode.USER_MISMATCH],
    [{ user: { subject: 'user-1', sessionId: 'session-2' } }, ErrorCode.SESSION_MISMATCH],
    [{ nonce: 'n2' }, ErrorCode.NONCE_MISMATCH]
  ];
  for (const [overrides, expected] of cases) {
    const result = validateBinding(record(), request(overrides), T0);
    assert.equal(result.ok, false);
    assert.equal(result.code, expected);
  }
});
