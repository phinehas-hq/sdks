/**
 * Phinehas Node.js / Express Middleware
 * Specification: Section 5.1
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  ThreatEvaluator,
  MemoryStore,
  RedisStore,
  PhinehasLogger,
  type PhinehasOptions,
  type BanStore,
  type StrikeEvent
} from '../../core/src/index.ts';
import { extractClientIp, isIpAllowed } from './ip.ts';
import { executeAction } from './actions.ts';

export type NextFunction = (err?: any) => void;

export type PhinehasMiddleware = (
  req: IncomingMessage & { originalUrl?: string },
  res: ServerResponse,
  next: NextFunction
) => Promise<void>;

/**
 * Creates a Phinehas active-defense security middleware instance.
 */
export function phinehas(options?: PhinehasOptions): PhinehasMiddleware {
  const evaluator = new ThreatEvaluator(options?.honeypots);
  const logger = new PhinehasLogger(options?.logging);
  const action = options?.action ?? 'terminate';
  const allowList = options?.allowList ?? ['127.0.0.1', '::1'];
  const banTtl = options?.storage?.ttl !== undefined ? options.storage.ttl : 3600;

  // Initialize storage layer
  let store: BanStore;
  const storeDriverName = options?.storage?.driver ?? 'memory';

  if (options?.storage?.driver === 'redis' && options.storage.client) {
    store = new RedisStore({
      client: options.storage.client,
      keyPrefix: options.storage.keyPrefix,
      defaultTtlSeconds: banTtl
    });
  } else {
    store = new MemoryStore({
      defaultTtlSeconds: banTtl
    });
  }

  return async function phinehasMiddleware(
    req: IncomingMessage & { originalUrl?: string },
    res: ServerResponse,
    next: NextFunction
  ): Promise<void> {
    try {
      const clientIp = extractClientIp(req, options?.proxy);

      // 1. Check AllowList (exempt trusted IPs/localhost)
      if (isIpAllowed(clientIp, allowList)) {
        return next();
      }

      // 2. Check if IP is already banned
      const isBanned = await store.isBanned(clientIp);
      if (isBanned) {
        const strike: StrikeEvent = {
          ip: clientIp,
          path: req.originalUrl || req.url || '/',
          method: req.method || 'GET',
          headers: req.headers as Record<string, string>,
          ruleMatched: 'explicit_trap',
          timestamp: new Date().toISOString()
        };

        logger.logStrike({
          strike,
          actionTaken: action,
          banStoreName: storeDriverName,
          banTtlSeconds: banTtl,
          userAgent: req.headers['user-agent'],
          host: req.headers.host
        });

        executeAction(action, { req, res });
        return;
      }

      // 3. Evaluate Request Path
      const targetPath = req.originalUrl || req.url || '/';
      const result = evaluator.evaluate(targetPath);

      if (result.isBlocked && result.ruleMatched) {
        // Active Threat Detected: Strike!
        await store.ban(clientIp, banTtl);

        const strike: StrikeEvent = {
          ip: clientIp,
          path: targetPath,
          method: req.method || 'GET',
          headers: req.headers as Record<string, string>,
          ruleMatched: result.ruleMatched,
          timestamp: new Date().toISOString()
        };

        logger.logStrike({
          strike,
          actionTaken: action,
          banStoreName: storeDriverName,
          banTtlSeconds: banTtl,
          userAgent: req.headers['user-agent'],
          host: req.headers.host
        });

        executeAction(action, { req, res });
        return;
      }

      // 4. Request is clean -> hand off to host application
      next();
    } catch {
      // 5. Graceful Fail-Open: security middleware must NEVER break the host application
      next();
    }
  };
}
