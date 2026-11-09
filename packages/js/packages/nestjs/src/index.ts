/**
 * @phinehas/nestjs
 * NestJS Module & Middleware for Phinehas Active Defense
 */

export { PhinehasModule, type DynamicModuleLike, type PhinehasModuleAsyncOptions } from './module.ts';
export { PhinehasMiddleware, type NestMiddlewareLike, type NestMiddlewareClass } from './middleware.ts';
export { PHINEHAS_OPTIONS } from './constants.ts';

// Re-export core options and contracts
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
