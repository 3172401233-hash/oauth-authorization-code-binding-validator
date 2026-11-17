import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AuthorizationCodeStore } from '../lib/code-store.js';
import { computeS256Challenge } from '../lib/pkce.js';
import { ErrorCode, ValidationError, toOAuthErrorBody } from '../lib/errors.js';

const TTL = 60_000;
const T0 = 1_700_000_000_000;

const USER = { subject: 'user-1', sessionId: 'session-1' };
const CLIENT = {
  clientId: 'client-a',
  redirectUri: 'https://app.example.com/cb'
};
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const CHALLENGE = computeS256Challenge(VERIFIER);
const NONCE = 'nonce-abc';

function makeStore(options = {}) {
  return new AuthorizationCodeStore({ ttlMs: TTL, ...options });
}

function issueCode(store, overrides = {}) {
  return store.issue({
    clientId: CLIENT.clientId,
    redirectUri: CLIENT.redirectUri,
    codeChallenge: CHALLENGE,
    codeChallengeMethod: 'S256',
    nonce: NONCE,
    user: USER,
    now: T0,
    ...overrides
  });
}

let nonceCounter = 0;
function issueUniqueCode(store, overrides = {}) {
  nonceCounter += 1;
  return issueCode(store, { nonce: `${NONCE}-${nonceCounter}`, ...overrides });
}

function redeemArgs(code, overrides = {}) {
  return {
    code,
    clientId: CLIENT.clientId,
    redirectUri: CLIENT.redirectUri,
    codeVerifier: VERIFIER,
    nonce: NONCE,
    user: USER,
    ...overrides
  };
}

async function assertRejectsWith(t, promise, expectedCode) {
  await t.test(`期望错误 ${expectedCode}`, async () => {
    await assert.rejects(
      promise,
      (error) => {
        assert.ok(error instanceof ValidationError);
        assert.equal(error.code, expectedCode);
        return true;
      }
    );
  });
}

test('合法兑换成功并返回 token', async () => {
  const store = makeStore();
  const code = issueCode(store);
  const result = await store.redeem(redeemArgs(code), { now: T0 + 1000 });
  assert.equal(result.ok, true);
  assert.equal(result.token.tokenType, 'Bearer');
  assert.equal(store.inspect(code).consumed, true);
  assert.equal(store.inspect(code).consumedAt, T0 + 1000);
});

test('换成另一个 client_id 被拒绝（客户端绑定）', async () => {
  const store = makeStore();
  const code = issueCode(store);
  await assert.rejects(
    store.redeem(redeemArgs(code, { clientId: 'client-evil' }), { now: T0 + 1000 }),
    (error) => error.code === ErrorCode.CLIENT_MISMATCH
  );
  assert.equal(store.inspect(code).consumed, false);
});

test('redirect URI 仅 query 参数不同即被拒绝（精确匹配）', async (t) => {
  const store = makeStore();
  const code = issueCode(store);
  const variants = [
    `${CLIENT.redirectUri}?extra=1`,
    `${CLIENT.redirectUri}?`,
    CLIENT.redirectUri.replace('/cb', '/cb/'),
    'https://app.example.com/cb?code=x',
    'https://app.example.com:443/cb',
    'http://app.example.com/cb'
  ];
  for (const redirectUri of variants) {
    await assertRejectsWith(
      t,
      store.redeem(redeemArgs(code, { redirectUri }), { now: T0 + 1000 }),
      ErrorCode.REDIRECT_URI_MISMATCH
    );
  }
  assert.equal(store.inspect(code).consumed, false);
});

test('用户与会话绑定：换用户或换会话均被拒绝', async (t) => {
  const store = makeStore();
  const code = issueCode(store);
  await assertRejectsWith(
    t,
    store.redeem(
      redeemArgs(code, { user: { subject: 'user-2', sessionId: 'session-1' } }),
      { now: T0 + 1000 }
    ),
    ErrorCode.USER_MISMATCH
  );
  await assertRejectsWith(
    t,
    store.redeem(
      redeemArgs(code, { user: { subject: 'user-1', sessionId: 'session-2' } }),
      { now: T0 + 1000 }
    ),
    ErrorCode.SESSION_MISMATCH
  );
});

test('PKCE verifier 错误、缺失、畸形均被拒绝且不消费授权码', async (t) => {
  const store = makeStore();
  const code = issueCode(store);
  await assertRejectsWith(
    t,
    store.redeem(redeemArgs(code, { codeVerifier: VERIFIER.slice(0, -1) + 'A' }), {
      now: T0 + 1000
    }),
    ErrorCode.PKCE_CHALLENGE_FAILED
  );
  await assertRejectsWith(
    t,
    store.redeem(redeemArgs(code, { codeVerifier: undefined }), { now: T0 + 1000 }),
    ErrorCode.PKCE_VERIFIER_MISSING
  );
  await assertRejectsWith(
    t,
    store.redeem(redeemArgs(code, { codeVerifier: 'bad' }), { now: T0 + 1000 }),
    ErrorCode.PKCE_VERIFIER_MALFORMED
  );
  assert.equal(store.inspect(code).consumed, false);
});

test('nonce 不一致被拒绝', async () => {
  const store = makeStore();
  const code = issueCode(store);
  await assert.rejects(
    store.redeem(redeemArgs(code, { nonce: 'nonce-tampered' }), { now: T0 + 1000 }),
    (error) => error.code === ErrorCode.NONCE_MISMATCH
  );
});

test('时钟边界：expiresAt 之前有效，到点即过期', async () => {
  const store = makeStore();
  const code = issueCode(store);
  assert.equal(store.inspect(code).expiresAt, T0 + TTL);

  const atLastMs = await store.redeem(redeemArgs(code), { now: T0 + TTL - 1 });
  assert.equal(atLastMs.ok, true);

  const freshCode = issueUniqueCode(store);
  await assert.rejects(
    store.redeem(redeemArgs(freshCode), { now: T0 + TTL }),
    (error) => error.code === ErrorCode.CODE_EXPIRED
  );
  await assert.rejects(
    store.redeem(redeemArgs(freshCode), { now: T0 + TTL + 5000 }),
    (error) => error.code === ErrorCode.CODE_EXPIRED
  );
});

test('并发兑换：只有一个成功，其余返回 code_consumed', async () => {
  const releaseSteps = [];
  const store = makeStore({
    issueToken: async () => {
      releaseSteps.push('token-start');
      await new Promise((resolve) => setImmediate(resolve));
      releaseSteps.push('token-end');
      return { accessToken: 'tok', tokenType: 'Bearer', expiresIn: 60 };
    }
  });
  const code = issueCode(store);

  const results = await Promise.allSettled([
    store.redeem(redeemArgs(code), { now: T0 + 1000 }),
    store.redeem(redeemArgs(code), { now: T0 + 1000 }),
    store.redeem(redeemArgs(code), { now: T0 + 1000 })
  ]);

  const fulfilled = results.filter((r) => r.status === 'fulfilled');
  const rejected = results.filter((r) => r.status === 'rejected');
  assert.equal(fulfilled.length, 1);
  assert.equal(fulfilled[0].value.token.accessToken, 'tok');
  assert.equal(rejected.length, 2);
  for (const entry of rejected) {
    assert.equal(entry.reason.code, ErrorCode.CODE_CONSUMED);
  }
  assert.deepEqual(releaseSteps, ['token-start', 'token-end']);
});

test('成功兑换后串行重试同样得到 code_consumed', async () => {
  const store = makeStore();
  const code = issueCode(store);
  await store.redeem(redeemArgs(code), { now: T0 + 1000 });
  await assert.rejects(
    store.redeem(redeemArgs(code), { now: T0 + 2000 }),
    (error) => error.code === ErrorCode.CODE_CONSUMED
  );
});

test('nonce 重放：同 client + 用户重复签发被拒绝，新 nonce 不受影响', async () => {
  const store = makeStore();
  issueCode(store, { nonce: 'n-1' });
  assert.throws(
    () => issueCode(store, { nonce: 'n-1' }),
    (error) => error.code === ErrorCode.NONCE_REPLAYED
  );
  const otherUserCode = issueCode(store, {
    nonce: 'n-1',
    user: { subject: 'user-2', sessionId: 'session-9' }
  });
  assert.ok(otherUserCode);
  const nextCode = issueCode(store, { nonce: 'n-2' });
  assert.ok(nextCode);
});

test('未知授权码返回 code_not_found', async () => {
  const store = makeStore();
  await assert.rejects(
    store.redeem(redeemArgs('00000000-0000-0000-0000-000000000000'), { now: T0 }),
    (error) => error.code === ErrorCode.CODE_NOT_FOUND
  );
});

test('错误映射：内部错误码映射到 RFC 6749/7636 协议错误', () => {
  assert.deepEqual(toOAuthErrorBody(ErrorCode.CODE_CONSUMED), {
    error: 'invalid_grant',
    error_description: '授权码已被消费，重复兑换被拒绝'
  });
  assert.deepEqual(toOAuthErrorBody(ErrorCode.REDIRECT_URI_MISMATCH), {
    error: 'invalid_request',
    error_description: 'redirect_uri 与授权请求时登记的值不匹配'
  });
  assert.deepEqual(toOAuthErrorBody(ErrorCode.PKCE_CHALLENGE_FAILED), {
    error: 'invalid_grant',
    error_description: 'code_verifier 与 code_challenge 不匹配'
  });
});

test('锁在失败后释放：不同授权码可并发，同一授权码失败后仍可重试成功', async () => {
  const store = makeStore();
  const nonceA = 'lock-nonce-a';
  const nonceB = 'lock-nonce-b';
  const codeA = issueCode(store, { nonce: nonceA });
  const codeB = issueCode(store, { nonce: nonceB });

  await assert.rejects(
    store.redeem(redeemArgs(codeA, { clientId: 'wrong' }), { now: T0 + 1000 }),
    (error) => error.code === ErrorCode.CLIENT_MISMATCH
  );

  const [a, b] = await Promise.all([
    store.redeem(redeemArgs(codeA, { nonce: nonceA }), { now: T0 + 1000 }),
    store.redeem(redeemArgs(codeB, { nonce: nonceB }), { now: T0 + 1000 })
  ]);
  assert.equal(a.ok, true);
  assert.equal(b.ok, true);
});

test('签发时强制 PKCE：缺 challenge 或非 S256 方法被拒绝', () => {
  const store = makeStore();
  assert.throws(
    () => issueCode(store, { codeChallenge: undefined }),
    (error) => error.code === ErrorCode.PKCE_CHALLENGE_MISSING
  );
  assert.throws(
    () => issueCode(store, { codeChallengeMethod: 'plain' }),
    (error) => error.code === ErrorCode.PKCE_METHOD_UNSUPPORTED
  );
});
