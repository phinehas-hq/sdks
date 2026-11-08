/**
 * Phinehas Core Type Definitions
 * Specification Version: 1.2.0
 */

export type BanAction = 'terminate' | 'reject' | 'tarpit';

export type LogFormat = 'compact' | 'structured';

export type RuleMatched = 'rfc8615_wildcard' | 'explicit_trap' | 'custom_trap';

export interface StrikeEvent {
  ip: string;
  path: string;
  method: string;
  headers: Record<string, string>;
  ruleMatched: RuleMatched;
  timestamp: string; // ISO 8601
}

export interface BanStore {
  /**
   * Check if an IP address is currently banned.
   * @param ip Remote IPv4 or IPv6 address string
   */
  isBanned(ip: string): Promise<boolean> | boolean;

  /**
   * Ban an IP address with an optional time-to-live in seconds.
   * @param ip Remote IP address string
   * @param ttlSeconds TTL in seconds. 0 or null denotes indefinite / permanent ban.
   */
  ban(ip: string, ttlSeconds?: number | null): Promise<void> | void;

  /**
   * Remove an IP address from the ban registry.
   * @param ip Remote IP address string
   */
  unban(ip: string): Promise<void> | void;

  /**
   * Optional cleanup / disposal hook
   */
  close?(): Promise<void> | void;
}

export interface StorageOptions {
  driver?: 'memory' | 'redis';
  client?: any;
  url?: string;
  keyPrefix?: string;
  ttl?: number | null; // Default: 3600 (1 hour)
}

export interface HoneypotsOptions {
  custom?: string[];
  excludeDefaults?: boolean;
}

export interface ProxyOptions {
  trust?: boolean;
  depth?: number;
  header?: string;
}

export interface LoggingOptions {
  enabled?: boolean;
  format?: LogFormat;
  onStrike?: (strike: StrikeEvent) => void;
}

export interface PhinehasOptions {
  storage?: StorageOptions;
  action?: BanAction;
  honeypots?: HoneypotsOptions;
  allowList?: string[];
  proxy?: ProxyOptions;
  logging?: LoggingOptions;
}

export interface EvaluationResult {
  isBlocked: boolean;
  ruleMatched?: RuleMatched;
  normalizedPath: string;
  reason?: string;
}
