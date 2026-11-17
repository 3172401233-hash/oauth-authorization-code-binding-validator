import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  computeS256Challenge,
  isValidVerifierFormat,
  verifyPkce
} from '../lib/pkce.js';
import { ErrorCode } from '../lib/errors.js';

const RFC_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const RFC_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

test('S256 与 RFC 7636 附录 B 测试向量一致', () => {
  assert.equal(computeS256Challenge(RFC_VERIFIER), RFC_CHALLENGE);
});

test('verifier 格式：43~128 位 unreserved 字符', () => {
  assert.equal(isValidVerifierFormat(RFC_VERIFIER), true);
  assert.equal(isValidVerifierFormat('a'.repeat(43)), true);
  assert.equal(isValidVerifierFormat('a'.repeat(128)), true);
  assert.equal(isValidVerifierFormat('a'.repeat(42)), false);
  assert.equal(isValidVerifierFormat('a'.repeat(129)), false);
  assert.equal(isValidVerifierFormat('has space'.padEnd(43, 'a')), false);
  assert.equal(isValidVerifierFormat('has/slash'.padEnd(43, 'a')), false);
  assert.equal(isValidVerifierFormat(undefined), false);
});

test('正确的 verifier 通过 S256 校验', () => {
  const error = verifyPkce({
    codeChallenge: RFC_CHALLENGE,
    codeChallengeMethod: 'S256',
    codeVerifier: RFC_VERIFIER
  });
  assert.equal(error, undefined);
});

test('verifier 混淆（单字符篡改）被拒绝', () => {
  const tampered = RFC_VERIFIER.slice(0, -1) + 'X';
  assert.notEqual(tampered, RFC_VERIFIER);
  const error = verifyPkce({
    codeChallenge: RFC_CHALLENGE,
    codeChallengeMethod: 'S256',
    codeVerifier: tampered
  });
  assert.equal(error, ErrorCode.PKCE_CHALLENGE_FAILED);
});

test('challenge 被混淆为等长字符串时仍被拒绝', () => {
  const tamperedChallenge = RFC_CHALLENGE.slice(0, -1) + 'x';
  const error = verifyPkce({
    codeChallenge: tamperedChallenge,
    codeChallengeMethod: 'S256',
    codeVerifier: RFC_VERIFIER
  });
  assert.equal(error, ErrorCode.PKCE_CHALLENGE_FAILED);
});

test('缺失、畸形 verifier 与非 S256 方法分别返回明确错误', () => {
  const base = { codeChallenge: RFC_CHALLENGE, codeChallengeMethod: 'S256' };
  assert.equal(
    verifyPkce({ ...base, codeVerifier: undefined }),
    ErrorCode.PKCE_VERIFIER_MISSING
  );
  assert.equal(
    verifyPkce({ ...base, codeVerifier: 'short' }),
    ErrorCode.PKCE_VERIFIER_MALFORMED
  );
  assert.equal(
    verifyPkce({ ...base, codeChallengeMethod: 'plain', codeVerifier: RFC_VERIFIER }),
    ErrorCode.PKCE_METHOD_UNSUPPORTED
  );
});
