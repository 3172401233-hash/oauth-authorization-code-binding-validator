/**
 * 按 key 串行化的异步互斥锁。同一 key 的临界区不会并发执行，
 * 不同 key 之间互不阻塞。
 */
export class KeyedMutex {
  #locks = new Map();

  async acquire(key) {
    let entry = this.#locks.get(key);
    if (!entry) {
      entry = { tail: Promise.resolve(), holders: 0 };
      this.#locks.set(key, entry);
    }
    entry.holders += 1;
    const previous = entry.tail;
    let release;
    const current = new Promise((resolve) => {
      release = resolve;
    });
    entry.tail = previous.then(() => current);
    await previous;
    return () => {
      release();
      entry.holders -= 1;
      if (entry.holders === 0) {
        this.#locks.delete(key);
      }
    };
  }
}
