# oauth-authorization-code-binding-validator

Node.js OAuth 2.0 授权码绑定校验库。解决两类常见漏洞：

- 授权码被拿到另一个 `client_id` 或另一个 `redirect_uri` 下仍能兑换；
- 同一授权码并发/重复兑换，每次都成功签发 token。

库实现 PKCE S256 校验、redirect URI 精确匹配、客户端与用户会话绑定、过期时间判断，
以及基于按码互斥锁的一次性原子兑换：并发请求中只有一个成功，其余得到明确的
`code_consumed` 错误。

## 协议字段

授权端点签发授权码时，以下字段随授权码持久化，token 端点兑换时逐一核对：

| 字段 | 来源 | 校验规则 |
| --- | --- | --- |
| `client_id` | 授权请求 | 兑换请求的 `client_id` 必须完全相同，否则 `client_mismatch` |
| `redirect_uri` | 授权请求 | 逐字符精确匹配（RFC 6749 §4.1.3），host/path 相同但 query 不同也拒绝 |
| `code_challenge` / `code_challenge_method` | 授权请求 | 强制 PKCE，仅支持 `S256`；`BASE64URL(SHA256(code_verifier))` 必须相等，常量时间比较 |
| `nonce` | 授权请求（OIDC） | 兑换时必须一致；同一 client + 用户下重复签发即视为重放 |
| 用户会话 | 登录态 | `subject` 与 `sessionId` 均须匹配，防止跨用户/跨会话使用 |
| `expires_at` | 签发时间 + TTL | `now >= expires_at` 即过期（到点失效，边界前一毫秒仍有效） |
| `consumed` / `consumed_at` | 兑换状态 | 成功兑换后立即置位，重复兑换返回 `code_consumed` |

`code_verifier` 格式遵循 RFC 7636 §4.1：43–128 个 `[A-Za-z0-9-._~]` 字符。

## 用法

```js
import { AuthorizationCodeStore, computeS256Challenge, toOAuthErrorBody } from './index.js';

const store = new AuthorizationCodeStore({ ttlMs: 60_000 });

// 授权端点
const code = store.issue({
  clientId: 'client-a',
  redirectUri: 'https://app.example.com/cb',
  codeChallenge: computeS256Challenge(codeVerifier),
  codeChallengeMethod: 'S256',
  nonce: 'openid-nonce',
  user: { subject: 'user-1', sessionId: 'session-1' }
});

// token 端点（并发安全，重复兑换只有一个成功）
try {
  const { token } = await store.redeem({
    code,
    clientId: 'client-a',
    redirectUri: 'https://app.example.com/cb',
    codeVerifier,
    nonce: 'openid-nonce',
    user: { subject: 'user-1', sessionId: 'session-1' }
  });
} catch (error) {
  // error.code 为内部错误码，error.oauthError / toOAuthErrorBody 给出协议响应
  const body = toOAuthErrorBody(error.code);
}
```

也可以直接使用无状态纯函数 `validateBinding(record, request, now)`，
把存储与时钟完全交给调用方（见 `lib/validator.js`）。

## 一次性兑换与原子锁

`AuthorizationCodeStore.redeem()` 对每个授权码通过 `KeyedMutex` 串行化，临界区内顺序为：

1. 获取该 `code` 的互斥锁（不同 code 互不阻塞）；
2. 查不到记录 → `code_not_found`；已 `consumed` → `code_consumed`；
3. 依次校验过期时间、client、redirect URI、用户、会话、PKCE、nonce；
4. 任一校验失败即释放锁，授权码保持未消费，可由合法请求重试；
5. 全部通过后**先**把 `consumed` 置 true 并记录 `consumedAt`，**再**签发 token；
6. `finally` 释放锁。

因此并发 N 个相同兑换请求时，仅 1 个成功，其余 N-1 个拿到 `code_consumed`，
且 token 签发函数只会被调用一次。

## 错误映射

内部错误码到 RFC 6749 §5.2 / RFC 7636 §4.6 token 端点错误的映射：

| 内部错误码 | OAuth `error` | 触发场景 |
| --- | --- | --- |
| `code_not_found` | `invalid_grant` | 授权码不存在 |
| `code_consumed` | `invalid_grant` | 授权码已消费（含并发重复兑换） |
| `code_expired` | `invalid_grant` | `now >= expires_at` |
| `client_mismatch` | `invalid_grant` | 兑换 `client_id` 与签发时不同 |
| `redirect_uri_mismatch` | `invalid_request` | redirect URI 非精确一致（RFC 7636 §4.6） |
| `user_mismatch` | `invalid_grant` | 用户 subject 不一致 |
| `session_mismatch` | `invalid_grant` | 会话 ID 不一致 |
| `pkce_challenge_missing` | `invalid_request` | 签发时缺少 `code_challenge` |
| `pkce_verifier_missing` | `invalid_request` | 兑换时缺少 `code_verifier` |
| `pkce_verifier_malformed` | `invalid_grant` | verifier 不符合 RFC 7636 字符集/长度 |
| `pkce_challenge_failed` | `invalid_grant` | S256 计算值与 challenge 不匹配 |
| `pkce_method_unsupported` | `invalid_grant` | `code_challenge_method` 不是 `S256` |
| `nonce_mismatch` | `invalid_grant` | 兑换 nonce 与登记值不一致 |
| `nonce_replayed` | `invalid_grant` | 同 client + 用户重复使用同一 nonce 签发 |

错误对象为 `ValidationError`，含 `code` 与 `oauthError` 属性；
`toOAuthErrorBody(code)` 返回可直接作为 HTTP 响应体的
`{ error, error_description }`。

## 目录结构

- `lib/pkce.js`：S256 challenge 计算、verifier 格式与常量时间校验；
- `lib/validator.js`：授权码绑定纯函数校验器与精确 URI 比较；
- `lib/mutex.js`：按 key 串行化的异步互斥锁；
- `lib/code-store.js`：授权码签发、nonce 重放防护与原子一次性兑换；
- `lib/errors.js`：错误码定义与协议错误映射。

## 测试

```bash
node --test
```

覆盖：RFC 7636 官方测试向量、verifier/challenge 混淆、redirect URI 参数差异、
客户端/用户/会话绑定、并发兑换（仅一个成功）、串行重放、nonce 重放与篡改、
过期时钟边界（`expiresAt - 1ms` 与 `expiresAt`）、失败后锁释放与错误映射。
