/**
 * Edge Runtime Remote IP Resolution for Next.js
 * Compatible with Vercel Edge, Cloudflare Workers, and Node.js Next.js Middleware.
 */

import type { ProxyOptions } from '@phinehas/core';

export interface EdgeRequestLike {
  ip?: string;
  url: string;
  nextUrl?: {
    pathname: string;
  };
  headers: Headers | Record<string, string | string[] | undefined>;
}

/**
 * Normalizes IPv6-mapped IPv4 addresses (::ffff:127.0.0.1 -> 127.0.0.1).
 */
export function normalizeIp(ip: string): string {
  if (!ip) return '127.0.0.1';
  let cleaned = ip.trim();
  if (cleaned.startsWith('::ffff:')) {
    cleaned = cleaned.substring(7);
  }
  return cleaned;
}

function getHeaderValue(headers: EdgeRequestLike['headers'], name: string): string | null {
  if (!headers) return null;

  if (typeof (headers as Headers).get === 'function') {
    return (headers as Headers).get(name);
  }

  const record = headers as Record<string, string | string[] | undefined>;
  const val = record[name.toLowerCase()] ?? record[name];
  if (Array.isArray(val)) {
    return val[0] || null;
  }
  return typeof val === 'string' ? val : null;
}

/**
 * Extracts the real client IP from a Next.js edge request.
 */
export function extractEdgeClientIp(req: EdgeRequestLike, proxyOpts?: ProxyOptions): string {
  // 1. Direct NextRequest IP (injected by Vercel / Edge platform)
  if (req.ip && typeof req.ip === 'string') {
    return normalizeIp(req.ip);
  }

  // 2. Custom header if configured (e.g. 'cf-connecting-ip', 'true-client-ip')
  if (proxyOpts?.header) {
    const custom = getHeaderValue(req.headers, proxyOpts.header);
    if (custom && custom.trim().length > 0) {
      return normalizeIp(custom.split(',')[0].trim());
    }
  }

  // 3. Cloudflare standard header
  const cfIp = getHeaderValue(req.headers, 'cf-connecting-ip');
  if (cfIp && cfIp.trim().length > 0) {
    return normalizeIp(cfIp.split(',')[0].trim());
  }

  // 4. X-Real-IP
  const realIp = getHeaderValue(req.headers, 'x-real-ip');
  if (realIp && realIp.trim().length > 0) {
    return normalizeIp(realIp.trim());
  }

  // 5. X-Forwarded-For
  const xff = getHeaderValue(req.headers, 'x-forwarded-for');
  if (xff && xff.trim().length > 0) {
    const ips = xff.split(',').map((item) => normalizeIp(item.trim()));

    if (proxyOpts?.depth && proxyOpts.depth > 0) {
      const targetIndex = ips.length - proxyOpts.depth;
      if (targetIndex >= 0 && targetIndex < ips.length) {
        return ips[targetIndex];
      }
    }

    return ips[0];
  }

  return '127.0.0.1';
}

/**
 * Checks whether an IP address is included in the exempt allowList.
 */
export function isIpAllowed(ip: string, allowList: readonly string[]): boolean {
  const normalized = normalizeIp(ip);

  for (const allowed of allowList) {
    const normalizedAllowed = normalizeIp(allowed);
    if (normalized === normalizedAllowed) {
      return true;
    }

    if (
      (normalized === '127.0.0.1' || normalized === '::1') &&
      (normalizedAllowed === '127.0.0.1' || normalizedAllowed === '::1' || normalizedAllowed === 'localhost')
    ) {
      return true;
    }
  }

  return false;
}
