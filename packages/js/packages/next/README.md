# `@phinehas/next`

> Edge & Server Middleware Security Guard for Next.js applications (App Router & Pages Router).

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Next.js](https://img.shields.io/badge/Next.js-13%2B-black.svg)](https://nextjs.org/)

---

## Overview

In Next.js Edge Middleware (V8 Isolates), direct TCP socket termination is not available. `@phinehas/next` provides `createPhinehasEdgeGuard()`, evaluating incoming edge requests before routing or React server components render, immediately dropping or blocking malicious probes with HTTP `403 Forbidden`.

---

## Installation

```bash
yarn add @phinehas/next @phinehas/core
```

---

## Quick Start (`middleware.ts`)

Create or update `middleware.ts` in the root of your Next.js project:

```typescript
import { NextRequest, NextResponse } from 'next/server';
import { createPhinehasEdgeGuard } from '@phinehas/next';

const guard = createPhinehasEdgeGuard({
  allowList: ['127.0.0.1'],
  logging: {
    format: 'structured',
    onStrike: (strike) => {
      console.warn(`[PHINEHAS STRIKE] Severed ${strike.ip} probing ${strike.path}`);
    }
  }
});

export async function middleware(req: NextRequest) {
  const result = await guard.check(req);

  if (result.isBlocked) {
    // Return the pre-configured zero-byte 403 Response
    return result.response || new NextResponse(null, { status: 403, statusText: 'Forbidden' });
  }

  return NextResponse.next();
}

export const config = {
  // Exclude static assets, Next.js internal chunks, and favicons
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

---

## Edge Runtime IP Detection

`@phinehas/next` automatically resolves the client IP address in edge environments using the following priority order:
1. `req.ip` (Injected automatically by Vercel Edge Runtime)
2. `cf-connecting-ip` (Cloudflare Workers / Enterprise proxy)
3. `x-real-ip`
4. `x-forwarded-for` (with depth resolution)

---

## License

Apache-2.0. Maintained by [Phinehas HQ](https://github.com/phinehas-hq).
