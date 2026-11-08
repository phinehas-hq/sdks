/**
 * Phinehas Structured & Compact Logger
 * Specification: Section 7
 */

import type { StrikeEvent, LoggingOptions, BanAction } from './types.ts';

export interface LogStrikePayload {
  strike: StrikeEvent;
  actionTaken: BanAction;
  banStoreName: string;
  banTtlSeconds: number | null;
  userAgent?: string;
  host?: string;
}

export class PhinehasLogger {
  private readonly enabled: boolean;
  private readonly format: 'compact' | 'structured';
  private readonly onStrikeCallback?: (strike: StrikeEvent) => void;

  constructor(options?: LoggingOptions) {
    this.enabled = options?.enabled ?? true;
    this.format = options?.format ?? 'structured';
    this.onStrikeCallback = options?.onStrike;
  }

  public logStrike(payload: LogStrikePayload): void {
    const { strike, actionTaken, banStoreName, banTtlSeconds, userAgent, host } = payload;

    // Trigger custom user hook if provided
    if (this.onStrikeCallback) {
      try {
        this.onStrikeCallback(strike);
      } catch {
        // Suppress user callback exceptions to preserve fail-open safety
      }
    }

    if (!this.enabled) {
      return;
    }

    if (this.format === 'compact') {
      const actionLabel = actionTaken === 'terminate' ? 'Severed' : 'Blocked';
      console.warn(`[PHINEHAS STRIKE] ${actionLabel} ${strike.ip} accessing ${strike.path}`);
      return;
    }

    const actionDescription =
      actionTaken === 'terminate'
        ? 'TCP_SOCKET_TERMINATED'
        : actionTaken === 'reject'
          ? 'HTTP_403_REJECTED'
          : 'TARPIT_ENFORCED';

    const structuredLog = {
      timestamp: strike.timestamp,
      level: 'WARN',
      event: 'PHINEHAS_SPEAR_STRIKE',
      actor: {
        ip: strike.ip,
        user_agent: userAgent || strike.headers['user-agent'] || 'unknown'
      },
      target: {
        path: strike.path,
        method: strike.method,
        host: host || strike.headers['host'] || 'unknown'
      },
      verdict: {
        rule_matched: strike.ruleMatched,
        action_taken: actionDescription,
        ban_store: banStoreName,
        ban_ttl_seconds: banTtlSeconds
      }
    };

    console.warn(JSON.stringify(structuredLog));
  }
}
