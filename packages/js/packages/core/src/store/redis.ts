/**
 * Distributed Redis BanStore Driver with L1 Shielding Cache
 * Specification: Section 3.2
 */

import type { BanStore } from '../types.ts';

export interface RedisStoreOptions {
  client: any; // Compatible with ioredis or node-redis
  keyPrefix?: string; // Default: 'phinehas:ban:'
  defaultTtlSeconds?: number | null; // Default: 3600
  l1TtlMs?: number; // L1 cache TTL in milliseconds (Default: 5000ms / 5s)
}

interface L1CacheEntry {
  isBanned: boolean;
  expiresAt: number;
}

export class RedisStore implements BanStore {
  private readonly client: any;
  private readonly prefix: string;
  private readonly defaultTtl: number | null;
  private readonly l1TtlMs: number;
  private readonly l1Cache: Map<string, L1CacheEntry>;

  constructor(options: RedisStoreOptions) {
    if (!options?.client) {
      throw new Error('[Phinehas] RedisStore requires an active Redis client instance (ioredis or redis).');
    }
    this.client = options.client;
    this.prefix = options.keyPrefix ?? 'phinehas:ban:';
    this.defaultTtl = options.defaultTtlSeconds !== undefined ? options.defaultTtlSeconds : 3600;
    this.l1TtlMs = options.l1TtlMs ?? 5000;
    this.l1Cache = new Map();
  }

  private getKey(ip: string): string {
    return `${this.prefix}${ip}`;
  }

  /**
   * Check if an IP is banned.
   * Leverages the in-memory L1 cache (5s TTL) before executing an outbound Redis GET.
   */
  public async isBanned(ip: string): Promise<boolean> {
    const now = Date.now();
    const l1 = this.l1Cache.get(ip);

    if (l1 && now < l1.expiresAt) {
      return l1.isBanned;
    }

    try {
      const key = this.getKey(ip);
      // Support both node-redis (get(key)) and ioredis (get(key))
      const res = await this.client.get(key);
      const isBanned = res !== null && res !== undefined;

      // Update L1 shielding cache
      this.l1Cache.set(ip, {
        isBanned,
        expiresAt: now + this.l1TtlMs
      });

      return isBanned;
    } catch {
      // Graceful fail-open: never crash host app if Redis is unreachable
      return false;
    }
  }

  /**
   * Ban an IP address in Redis.
   */
  public async ban(ip: string, ttlSeconds?: number | null): Promise<void> {
    const effectiveTtl = ttlSeconds !== undefined ? ttlSeconds : this.defaultTtl;
    const key = this.getKey(ip);

    try {
      if (effectiveTtl && effectiveTtl > 0) {
        if (typeof this.client.set === 'function') {
          // Supports both `set(key, val, 'EX', ttl)` and `set(key, val, { EX: ttl })`
          try {
            await this.client.set(key, '1', 'EX', effectiveTtl);
          } catch {
            await this.client.set(key, '1', { EX: effectiveTtl });
          }
        } else if (typeof this.client.setex === 'function') {
          await this.client.setex(key, effectiveTtl, '1');
        }
      } else {
        // Permanent ban (ttl: 0 or null)
        await this.client.set(key, '1');
      }

      // Update L1 cache immediately
      this.l1Cache.set(ip, {
        isBanned: true,
        expiresAt: Date.now() + this.l1TtlMs
      });
    } catch {
      // Graceful fail-open
    }
  }

  /**
   * Remove an IP address ban from Redis and invalidate L1 cache.
   */
  public async unban(ip: string): Promise<void> {
    const key = this.getKey(ip);
    this.l1Cache.delete(ip);

    try {
      if (typeof this.client.del === 'function') {
        await this.client.del(key);
      }
    } catch {
      // Graceful fail-open
    }
  }

  public close(): void {
    this.l1Cache.clear();
  }
}
