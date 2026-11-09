/**
 * @phinehas/node
 * Active Defense Security Middleware for Node.js & Express
 */

export { phinehas, type PhinehasMiddleware, type NextFunction } from './middleware.ts';
export { extractClientIp, normalizeIp, isIpAllowed } from './ip.ts';
export { executeAction, type ActionContext } from './actions.ts';

// Re-export core contracts
export type {
  PhinehasOptions,
  StrikeEvent,
  BanAction,
  BanStore,
  StorageOptions,
  HoneypotsOptions,
  ProxyOptions,
  LoggingOptions
} from '@phinehas/core';
