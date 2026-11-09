/**
 * @phinehas/next
 * Next.js Edge & Server Middleware Guard
 */

export {
  createPhinehasEdgeGuard,
  type PhinehasEdgeGuard,
  type PhinehasEdgeResult
} from './guard.ts';

export {
  extractEdgeClientIp,
  normalizeIp,
  isIpAllowed,
  type EdgeRequestLike
} from './ip.ts';

// Re-export core contracts
export type {
  PhinehasOptions,
  StrikeEvent,
  BanAction,
  BanStore,
  StorageOptions,
  HoneypotsOptions,
  ProxyOptions,
  LoggingOptions,
  RuleMatched
} from '@phinehas/core';
