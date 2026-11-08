/**
 * @phinehas/core
 * Active Defense Security Middleware Engine
 */

export * from './types.ts';
export { normalizePath, safeUrlDecode, resolvePathTraversal } from './normalizer.ts';
export { ThreatEvaluator } from './evaluator.ts';
export { DEFAULT_EXPLICIT_TRAPS, RFC8615_PATTERN } from './traps.ts';
export { MemoryStore, type MemoryStoreOptions, RedisStore, type RedisStoreOptions } from './store/index.ts';
export { PhinehasLogger, type LogStrikePayload } from './logger.ts';
