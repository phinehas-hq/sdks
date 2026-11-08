/**
 * Next.js Edge & Server Middleware Guard
 * Specification: Section 5.3
 */

import {
  ThreatEvaluator,
  MemoryStore,
  RedisStore,
  PhinehasLogger,
  type PhinehasOptions,
  type BanStore,
  type StrikeEvent,
  type RuleMatched
} from '../../core/src/index.ts';
import { extractEdgeClientIp, isIpAllowed, type EdgeRequestLike } from './ip.ts';

export interface PhinehasEdgeResult {
  isBlocked: boolean;
  ruleMatched?: RuleMatched;
  normalizedPath: string;
  response?: Response;
}

export interface PhinehasEdgeGuard {
  check(req: EdgeRequestLike): Promise<PhinehasEdgeResult>;
  close?(): void;
}

function createForbiddenResponse(): Response {
  return new Response(null, {
    status: 403,
    statusText: 'Forbidden',
    headers: {
      'Content-Length': '0',
      'Connection': 'close',
      'X-Phinehas-Verdict': 'blocked'
    }
  });
}

function extractPathname(req: EdgeRequestLike): string {
  if (req.nextUrl?.pathname) {
    return req.nextUrl.pathname;
  }

  try {
    const parsed = new URL(req.url, 'http://localhost');
    return parsed.pathname;
  } catch {
    return req.url || '/';
  }
}

function extractHeadersRecord(req: EdgeRequestLike): Record<string, string> {
  const result: Record<string, string> = {};
  if (!req.headers) return result;

  if (typeof (req.headers as Headers).forEach === 'function') {
    (req.headers as Headers).forEach((val, key) => {
      result[key.toLowerCase()] = val;
    });
    return result;
  }

  const record = req.headers as Record<string, string | string[] | undefined>;
  for (const [key, val] of Object.entries(record)) {
    if (typeof val === 'string') {
      result[key.toLowerCase()] = val;
    } else if (Array.isArray(val) && val[0]) {
      result[key.toLowerCase()] = val[0];
    }
  }

  return result;
}

/**
 * Creates a Phinehas Edge Guard for Next.js Middleware.
 */
export function createPhinehasEdgeGuard(options?: PhinehasOptions): PhinehasEdgeGuard {
  const evaluator = new ThreatEvaluator(options?.honeypots);
  const logger = new PhinehasLogger(options?.logging);
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

  return {
    async check(req: EdgeRequestLike): Promise<PhinehasEdgeResult> {
      const rawPath = extractPathname(req);

      try {
        const clientIp = extractEdgeClientIp(req, options?.proxy);

        // 1. Allowlist check
        if (isIpAllowed(clientIp, allowList)) {
          return {
            isBlocked: false,
            normalizedPath: rawPath
          };
        }

        const headers = extractHeadersRecord(req);

        // 2. Check if IP is already banned
        const isBanned = await store.isBanned(clientIp);
        if (isBanned) {
          const strike: StrikeEvent = {
            ip: clientIp,
            path: rawPath,
            method: 'GET',
            headers,
            ruleMatched: 'explicit_trap',
            timestamp: new Date().toISOString()
          };

          logger.logStrike({
            strike,
            actionTaken: 'reject',
            banStoreName: storeDriverName,
            banTtlSeconds: banTtl,
            userAgent: headers['user-agent'],
            host: headers.host
          });

          return {
            isBlocked: true,
            ruleMatched: 'explicit_trap',
            normalizedPath: rawPath,
            response: createForbiddenResponse()
          };
        }

        // 3. Evaluate Request Path
        const result = evaluator.evaluate(rawPath);

        if (result.isBlocked && result.ruleMatched) {
          await store.ban(clientIp, banTtl);

          const strike: StrikeEvent = {
            ip: clientIp,
            path: rawPath,
            method: 'GET',
            headers,
            ruleMatched: result.ruleMatched,
            timestamp: new Date().toISOString()
          };

          logger.logStrike({
            strike,
            actionTaken: 'reject',
            banStoreName: storeDriverName,
            banTtlSeconds: banTtl,
            userAgent: headers['user-agent'],
            host: headers.host
          });

          return {
            isBlocked: true,
            ruleMatched: result.ruleMatched,
            normalizedPath: result.normalizedPath,
            response: createForbiddenResponse()
          };
        }

        return {
          isBlocked: false,
          normalizedPath: result.normalizedPath
        };
      } catch {
        // 4. Graceful Fail-Open
        return {
          isBlocked: false,
          normalizedPath: rawPath
        };
      }
    },

    close() {
      if (typeof store.close === 'function') {
        store.close();
      }
    }
  };
}
