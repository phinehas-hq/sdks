import test from 'node:test';
import assert from 'node:assert/strict';
import { RedisStore } from '../src/index.ts';

test('RedisStore: L1 Shielding Cache & Fail-Open Behavior', async () => {
  let networkCalls = 0;
  const mockStorage = new Map<string, string>();

  const mockRedisClient = {
    async get(key: string) {
      networkCalls++;
      return mockStorage.get(key) || null;
    },
    async set(key: string, val: string, _mode?: string, _ttl?: number) {
      mockStorage.set(key, val);
    },
    async del(key: string) {
      mockStorage.delete(key);
    }
  };

  const redisStore = new RedisStore({
    client: mockRedisClient,
    keyPrefix: 'test:phinehas:ban:',
    defaultTtlSeconds: 3600,
    l1TtlMs: 200 // 200ms for testing L1 eviction
  });

  // Ban IP
  await redisStore.ban('192.168.1.50', 3600);
  assert.strictEqual(mockStorage.get('test:phinehas:ban:192.168.1.50'), '1');

  // First isBanned query should hit L1 cache (populated on ban), 0 network calls
  assert.strictEqual(await redisStore.isBanned('192.168.1.50'), true);
  assert.strictEqual(networkCalls, 0);

  // Uncached IP query -> 1 network call
  assert.strictEqual(await redisStore.isBanned('10.0.0.1'), false);
  assert.strictEqual(networkCalls, 1);

  // Second query for same uncached IP within L1 TTL -> still 1 network call (L1 shield active)
  assert.strictEqual(await redisStore.isBanned('10.0.0.1'), false);
  assert.strictEqual(networkCalls, 1);

  // Unban clears key and L1 cache
  await redisStore.unban('192.168.1.50');
  assert.strictEqual(mockStorage.has('test:phinehas:ban:192.168.1.50'), false);

  // Test Fail-Open: Network failure on Redis client should return false instead of throwing
  const brokenClient = {
    async get() {
      throw new Error('ECONNREFUSED: Redis cluster partitioned');
    },
    async set() {
      throw new Error('READONLY: Replica node');
    }
  };

  const faultTolerantStore = new RedisStore({
    client: brokenClient
  });

  // Must not throw exception
  const result = await faultTolerantStore.isBanned('8.8.8.8');
  assert.strictEqual(result, false, 'Expected fail-open return false on Redis exception');

  redisStore.close();
  faultTolerantStore.close();
});
