/**
 * Remote Client IP Resolution
 * Supports reverse proxies, custom cloud headers (Cloudflare, AWS ALB), and CIDR/localhost allowlisting.
 */

import type { IncomingMessage } from 'node:http';
import type { ProxyOptions } from '@phinehas/core';

/**
 * Normalizes IPv6-mapped IPv4 addresses (e.g. ::ffff:127.0.0.1 -> 127.0.0.1).
 */
export function normalizeIp(ip: string): string {
  if (!ip) return '127.0.0.1';
  let cleaned = ip.trim();
  if (cleaned.startsWith('::ffff:')) {
    cleaned = cleaned.substring(7);
  }
  return cleaned;
}

/**
 * Extracts the real client IP address from the request based on proxy configurations.
 */
export function extractClientIp(req: IncomingMessage, proxyOpts?: ProxyOptions): string {
  const socketIp = req.socket?.remoteAddress ? normalizeIp(req.socket.remoteAddress) : '127.0.0.1';

  if (!proxyOpts?.trust) {
    return socketIp;
  }

  // 1. Check custom cloud header if configured (e.g. 'cf-connecting-ip', 'true-client-ip')
  if (proxyOpts.header) {
    const customHeaderVal = req.headers[proxyOpts.header.toLowerCase()];
    if (typeof customHeaderVal === 'string' && customHeaderVal.trim().length > 0) {
      return normalizeIp(customHeaderVal.split(',')[0].trim());
    }
  }

  // 2. Check X-Forwarded-For header
  const xForwardedFor = req.headers['x-forwarded-for'];
  if (typeof xForwardedFor === 'string' && xForwardedFor.trim().length > 0) {
    const ips = xForwardedFor.split(',').map((item) => normalizeIp(item.trim()));

    if (proxyOpts.depth && proxyOpts.depth > 0) {
      // Pick the IP according to proxy depth (counting from the rightmost hop)
      const targetIndex = ips.length - proxyOpts.depth;
      if (targetIndex >= 0 && targetIndex < ips.length) {
        return ips[targetIndex];
      }
    }

    // Default to the first (client) IP in the chain
    return ips[0];
  }

  return socketIp;
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

    // Handle simple localhost aliases
    if (
      (normalized === '127.0.0.1' || normalized === '::1') &&
      (normalizedAllowed === '127.0.0.1' || normalizedAllowed === '::1' || normalizedAllowed === 'localhost')
    ) {
      return true;
    }
  }

  return false;
}
