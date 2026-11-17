import { randomUUID } from 'node:crypto';
import { KeyedMutex } from './mutex.js';
import { validateBinding } from './validator.js';
import { ErrorCode, ValidationError } from './errors.js';

const DEFAULT_TTL_MS = 60_000;

async function defaultIssueToken() {
  await Promise.resolve();
  return {
    accessToken: randomUUID(),
    tokenType: 'Bearer',
    expiresIn: 3600
  };
}

/**
 * 授权码存储。内存实现，生产环境可把 Map 换成数据库，
 * 但 redeem 的“加锁 -> 校验 -> 标记消费 -> 发 token”顺序必须保持。
 */
export class AuthorizationCodeStore {
  #codes = new Map();
  #usedNonces = new Set();
  #mutex = new KeyedMutex();
  #ttlMs;
  #issueToken;

  constructor({ ttlMs = DEFAULT_TTL_MS, issueToken } = {}) {
    this.#ttlMs = ttlMs;
    this.#issueToken = issueToken ?? defaultIssueToken;
  }

  /**
   * 授权端点：把授权请求的全部绑定信息持久化到授权码上。
   * nonce 在同一 client + 用户下不得重复，防止重放授权请求。
   */
  issue({
    clientId,
    redirectUri,
    codeChallenge,
    codeChallengeMethod = 'S256',
    nonce = null,
    user,
    now = Date.now()
  }) {
    if (codeChallengeMethod !== 'S256') {
      throw new ValidationError(ErrorCode.PKCE_METHOD_UNSUPPORTED);
    }
    if (!codeChallenge) {
      throw new ValidationError(ErrorCode.PKCE_CHALLENGE_MISSING);
    }
    if (nonce !== null && nonce !== undefined) {
      const nonceKey = `${clientId}\u0000${user.subject}\u0000${nonce}`;
      if (this.#usedNonces.has(nonceKey)) {
        throw new ValidationError(ErrorCode.NONCE_REPLAYED);
      }
      this.#usedNonces.add(nonceKey);
    }

    const code = randomUUID();
    this.#codes.set(code, {
      code,
      clientId,
      redirectUri,
      codeChallenge,
      codeChallengeMethod,
      nonce: nonce ?? null,
      user: { subject: user.subject, sessionId: user.sessionId },
      issuedAt: now,
      expiresAt: now + this.#ttlMs,
      consumed: false,
      consumedAt: null
    });
    return code;
  }

  /**
   * token 端点：按授权码加互斥锁后完成一次性原子兑换。
   * 并发请求中只有一个能成功，其余得到 code_consumed。
   */
  async redeem(request, { now = Date.now() } = {}) {
    const release = await this.#mutex.acquire(request.code);
    try {
      const record = this.#codes.get(request.code);
      if (!record) {
        throw new ValidationError(ErrorCode.CODE_NOT_FOUND);
      }

      const result = validateBinding(
        record,
        {
          clientId: request.clientId,
          redirectUri: request.redirectUri,
          codeVerifier: request.codeVerifier,
          nonce: request.nonce ?? null,
          user: request.user
        },
        now
      );
      if (!result.ok) {
        throw new ValidationError(result.code);
      }

      record.consumed = true;
      record.consumedAt = now;

      const token = await this.#issueToken(record);
      return {
        ok: true,
        token,
        consumedAt: record.consumedAt
      };
    } finally {
      release();
    }
  }

  /** 测试与排障用的只读视图。 */
  inspect(code) {
    const record = this.#codes.get(code);
    return record ? { ...record, user: { ...record.user } } : undefined;
  }
}
