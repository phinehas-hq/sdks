/**
 * In-Memory LRU BanStore Driver
 * Specification: Section 3.1
 * Hard allocation cap of 25,000 IP entries with O(1) LRU eviction.
 */

import type { BanStore } from '../types.ts';

interface LRUNode {
  ip: string;
  expiresAt: number | null; // epoch ms or null if permanent
  prev: LRUNode | null;
  next: LRUNode | null;
}

export interface MemoryStoreOptions {
  maxCapacity?: number; // Default: 25,000 entries (<5MB heap)
  defaultTtlSeconds?: number | null; // Default: 3600s
}

export class MemoryStore implements BanStore {
  private readonly maxCapacity: number;
  private readonly defaultTtl: number | null;
  private readonly map: Map<string, LRUNode>;
  private head: LRUNode | null = null;
  private tail: LRUNode | null = null;

  constructor(options?: MemoryStoreOptions) {
    this.maxCapacity = options?.maxCapacity ?? 25000;
    this.defaultTtl = options?.defaultTtlSeconds !== undefined ? options.defaultTtlSeconds : 3600;
    this.map = new Map();
  }

  /**
   * Current number of stored IP entries in memory.
   */
  public get size(): number {
    return this.map.size;
  }

  /**
   * Check if an IP address is actively banned.
   * Expired keys are automatically purged upon access.
   */
  public isBanned(ip: string): boolean {
    const node = this.map.get(ip);
    if (!node) {
      return false;
    }

    const now = Date.now();
    if (node.expiresAt !== null && now > node.expiresAt) {
      // Key expired: purge immediately
      this.removeNode(node);
      this.map.delete(ip);
      return false;
    }

    // Refresh LRU position to head
    this.moveToHead(node);
    return true;
  }

  /**
   * Register a ban for an IP address.
   * Automatically evicts the least recently used entry if capacity is reached.
   */
  public ban(ip: string, ttlSeconds?: number | null): void {
    const effectiveTtl = ttlSeconds !== undefined ? ttlSeconds : this.defaultTtl;
    const expiresAt = effectiveTtl && effectiveTtl > 0 ? Date.now() + effectiveTtl * 1000 : null;

    const existing = this.map.get(ip);
    if (existing) {
      existing.expiresAt = expiresAt;
      this.moveToHead(existing);
      return;
    }

    // Capacity enforcement
    if (this.map.size >= this.maxCapacity) {
      this.evictLeastRecentlyUsed();
    }

    const newNode: LRUNode = {
      ip,
      expiresAt,
      prev: null,
      next: null
    };

    this.addToHead(newNode);
    this.map.set(ip, newNode);
  }

  /**
   * Remove an IP address from the ban store.
   */
  public unban(ip: string): void {
    const node = this.map.get(ip);
    if (node) {
      this.removeNode(node);
      this.map.delete(ip);
    }
  }

  /**
   * Clear all entries.
   */
  public close(): void {
    this.map.clear();
    this.head = null;
    this.tail = null;
  }

  // --- Internal Doubly-Linked List Primitives ---

  private addToHead(node: LRUNode): void {
    node.next = this.head;
    node.prev = null;

    if (this.head !== null) {
      this.head.prev = node;
    }
    this.head = node;

    if (this.tail === null) {
      this.tail = node;
    }
  }

  private removeNode(node: LRUNode): void {
    if (node.prev !== null) {
      node.prev.next = node.next;
    } else {
      this.head = node.next;
    }

    if (node.next !== null) {
      node.next.prev = node.prev;
    } else {
      this.tail = node.prev;
    }

    node.prev = null;
    node.next = null;
  }

  private moveToHead(node: LRUNode): void {
    if (this.head === node) return;
    this.removeNode(node);
    this.addToHead(node);
  }

  private evictLeastRecentlyUsed(): void {
    if (this.tail === null) return;
    const oldest = this.tail;
    this.removeNode(oldest);
    this.map.delete(oldest.ip);
  }
}
