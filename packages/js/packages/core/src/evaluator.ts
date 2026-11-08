/**
 * Phinehas Threat Detection Evaluator
 * Specification: Section 2
 */

import { normalizePath } from './normalizer.ts';
import { DEFAULT_EXPLICIT_TRAPS, RFC8615_PATTERN } from './traps.ts';
import type { EvaluationResult, HoneypotsOptions } from './types.ts';

export class ThreatEvaluator {
  private readonly explicitTraps: Set<string>;
  private readonly customTraps: Set<string>;
  private readonly prefixTraps: string[];

  constructor(options?: HoneypotsOptions) {
    const defaultTraps = options?.excludeDefaults ? [] : DEFAULT_EXPLICIT_TRAPS;
    this.explicitTraps = new Set(defaultTraps);

    this.customTraps = new Set((options?.custom || []).map((p) => normalizePath(p)));

    // Categorize prefix traps (e.g. /wp-admin, /actuator, /phpmyadmin)
    this.prefixTraps = Array.from(this.explicitTraps).filter((trap) => !trap.includes('.'));
  }

  /**
   * Evaluates a request path against the threat detection pipeline:
   * 1. Path Normalization (anti-bypass)
   * 2. RFC 8615 Wildcard Rule
   * 3. Custom Honeypot Traps
   * 4. Explicit Non-Dot Traps Registry
   */
  public evaluate(rawPath: string): EvaluationResult {
    const normalized = normalizePath(rawPath);

    // 1. Check RFC 8615 Wildcard Rule
    if (RFC8615_PATTERN.test(normalized)) {
      return {
        isBlocked: true,
        ruleMatched: 'rfc8615_wildcard',
        normalizedPath: normalized,
        reason: `Matched RFC 8615 hidden path wildcard: ${normalized}`
      };
    }

    // 2. Check Custom Honeypots
    for (const custom of this.customTraps) {
      if (normalized === custom || normalized.startsWith(custom + '/')) {
        return {
          isBlocked: true,
          ruleMatched: 'custom_trap',
          normalizedPath: normalized,
          reason: `Matched custom honeypot trap: ${custom}`
        };
      }
    }

    // 3. Check Explicit Non-Dot Traps (Exact match or set lookup)
    if (this.explicitTraps.has(normalized)) {
      return {
        isBlocked: true,
        ruleMatched: 'explicit_trap',
        normalizedPath: normalized,
        reason: `Matched explicit threat signature: ${normalized}`
      };
    }

    // 4. Check Explicit Prefix Traps (e.g., /wp-admin/foo, /actuator/bar)
    for (const prefix of this.prefixTraps) {
      if (normalized.startsWith(prefix + '/')) {
        return {
          isBlocked: true,
          ruleMatched: 'explicit_trap',
          normalizedPath: normalized,
          reason: `Matched explicit prefix threat signature: ${prefix}`
        };
      }
    }

    return {
      isBlocked: false,
      normalizedPath: normalized
    };
  }
}
