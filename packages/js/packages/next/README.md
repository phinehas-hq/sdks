# `@phinehas/next`

> Edge & Server Middleware Security Guard for Next.js applications (App Router & Pages Router).

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../../../LICENSE)
[![Next.js](https://img.shields.io/badge/Next.js-13%2B-black.svg)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict-blue.svg)](https://www.typescriptlang.org/)
[![Compliance Parity](https://img.shields.io/badge/compliance-100%25-brightgreen.svg)](../../../../compliance/)

---

## 1. Overview & Edge Runtime Architecture

In Next.js Edge Middleware (running inside V8 Isolates across Vercel, Cloudflare, or AWS CloudFront), direct low-level TCP socket destruction (`req.socket.destroy()`) is not available due to runtime sandbox restrictions.

`@phinehas/next` provides `createPhinehasEdgeGuard()`, evaluating incoming edge requests at the extreme perimeter before Next.js routing, React Server Components (RSC), or API routes execute. When malicious reconnaissance is detected, it terminates the request with a **zero-byte HTTP `403 Forbidden` response (`Content-Length: 0`, `Connection: close`)**, ensuring backend databases and compute workers are never invoked.

---

## 2. Installation

Install using **Yarn**:
```bash
yarn add @phinehas/next @phinehas/core
```

---

## 3. Production Quick Start (`middleware.ts`)

Create or update `middleware.ts` in your Next.js project root (or inside `src/`):

```typescript
import { NextRequest, NextResponse } from 'next/server';
import { createPhinehasEdgeGuard } from '@phinehas/next';

// =========================================================================
// INITIALIZE EDGE GUARD (Required vs Optional Showcase)
// =========================================================================
const phinehasGuard = createPhinehasEdgeGuard({
  // [OPTIONAL - DEFAULT: in-process LRU store with 3600s TTL]
  storage: {
    driver: 'memory',
    ttl: 86400, // 24-hour ban duration for attacking IPs
  },

  // [PRODUCTION RECOMMENDED - DEFAULT: ['127.0.0.1', '::1']]
  // Whitelist internal services, staging IPs, or health monitors
  allowList: [
    '127.0.0.1',
    '::1',
  ],

  // [OPTIONAL - DEFAULT: built-in traps + RFC 8615 dotfiles]
  honeypots: {
    // Custom paths or regex patterns to protect internal Next.js routes
    custom: [
      /^\/_next\/data\/staging-secrets\.json$/,
      /^\/api\/internal(\/.*)?$/,
      '/debug/pprof',
    ],
    excludeDefaults: false,
  },

  // [OPTIONAL - DEFAULT: { format: 'structured' }]
  logging: {
    format: 'structured',
    onStrike: (strike) => {
      console.warn(`[PHINEHAS EDGE STRIKE] Blocked ${strike.ip} probing ${strike.path}`, {
        rule: strike.ruleMatched,
        timestamp: strike.timestamp,
      });
    },
  },
});

// [REQUIRED] Export the standard Next.js middleware handler
export async function middleware(req: NextRequest) {
  const result = await phinehasGuard.check(req);

  if (result.isBlocked) {
    // Returns pre-configured zero-byte 403 Forbidden with Connection: close
    return result.response || new NextResponse(null, { status: 403, statusText: 'Forbidden' });
  }

  return NextResponse.next();
}

// [PRODUCTION RECOMMENDED] Match all paths except static chunks, images, and favicons
export const config = {
  matcher: [
    /*
     * Match all request paths except for:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public files (svg, png, jpg, etc.)
     */
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
};
```

---

## 4. Edge Runtime IP Detection

In serverless edge environments, `@phinehas/next` automatically resolves the true client IP using the following priority hierarchy:

1. **`req.ip`** (Automatically populated by Vercel Edge Runtime)
2. **`cf-connecting-ip`** (Cloudflare Workers & Enterprise edge)
3. **`true-client-ip`** (Akamai CDN edge)
4. **`x-real-ip`** (Nginx / HAProxy ingress)
5. **`x-forwarded-for`** (Standard reverse proxy chain with hop traversal)

---

## 5. Testing Next.js Guards in Jest / Vitest

You can easily unit test your Next.js edge guard without starting a live web server:

```typescript
import { createPhinehasEdgeGuard } from '@phinehas/next';

describe('Phinehas Next.js Edge Guard', () => {
  const guard = createPhinehasEdgeGuard({
    allowList: ['127.0.0.1'],
  });

  function createMockRequest(pathname: string, ip: string = '203.0.113.195') {
    return {
      url: `https://example.com${pathname}`,
      nextUrl: { pathname },
      headers: {
        'x-forwarded-for': ip,
      },
    };
  }

  it('allows benign user traffic', async () => {
    const req = createMockRequest('/dashboard/analytics');
    const result = await guard.check(req as any);
    expect(result.isBlocked).toBe(false);
  });

  it('safely allows RFC 8615 .well-known discovery endpoints', async () => {
    const req = createMockRequest('/.well-known/apple-app-site-association');
    const result = await guard.check(req as any);
    expect(result.isBlocked).toBe(false);
  });

  it('intercepts and blocks dotfile scans', async () => {
    const req = createMockRequest('/.env.production');
    const result = await guard.check(req as any);
    expect(result.isBlocked).toBe(true);
    expect(result.ruleMatched).toBe('rfc8615_wildcard');
    expect(result.response?.status).toBe(403);
  });
});
```

---

## 6. Navigation

* [Root SDK Documentation](../../../../README.md)
* [Core Engine Guide (`@phinehas/core`)](../core/README.md)
* [Node.js & Express Middleware (`@phinehas/node`)](../node/README.md)
* [NestJS Module (`@phinehas/nestjs`)](../nestjs/README.md)

---

## 7. License

Licensed under the [Apache-2.0 License](../../../../LICENSE). Maintained by [Phinehas HQ](https://github.com/phinehas-hq).
