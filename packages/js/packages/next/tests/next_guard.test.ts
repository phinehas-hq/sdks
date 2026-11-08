import test from 'node:test';
import assert from 'node:assert/strict';
import { createPhinehasEdgeGuard, extractEdgeClientIp } from '../src/index.ts';

function createMockNextRequest(
  urlPath: string,
  headers: Record<string, string> = {},
  ip?: string
) {
  return {
    url: `https://example.com${urlPath}`,
    nextUrl: {
      pathname: urlPath
    },
    ip,
    headers: new Headers(headers)
  };
}

test('Next.js Edge IP Extraction', () => {
  // 1. Native NextRequest.ip
  const reqWithIp = createMockNextRequest('/api', {}, '198.51.100.9');
  assert.strictEqual(extractEdgeClientIp(reqWithIp), '198.51.100.9');

  // 2. Cloudflare header
  const cfReq = createMockNextRequest('/api', { 'cf-connecting-ip': '203.0.113.10' });
  assert.strictEqual(extractEdgeClientIp(cfReq), '203.0.113.10');

  // 3. X-Real-IP
  const realIpReq = createMockNextRequest('/api', { 'x-real-ip': '192.0.2.45' });
  assert.strictEqual(extractEdgeClientIp(realIpReq), '192.0.2.45');

  // 4. X-Forwarded-For with depth
  const xffReq = createMockNextRequest('/api', { 'x-forwarded-for': '1.1.1.1, 2.2.2.2, 3.3.3.3' });
  assert.strictEqual(extractEdgeClientIp(xffReq, { trust: true, depth: 1 }), '3.3.3.3');
  assert.strictEqual(extractEdgeClientIp(xffReq, { trust: true }), '1.1.1.1');
});

test('Next.js Edge Guard: Clean Route Pass-Through', async () => {
  const guard = createPhinehasEdgeGuard();
  const req = createMockNextRequest('/dashboard');

  const result = await guard.check(req);
  assert.strictEqual(result.isBlocked, false);
  assert.strictEqual(result.normalizedPath, '/dashboard');
  assert.strictEqual(result.response, undefined);

  guard.close?.();
});

test('Next.js Edge Guard: RFC 8615 Trapping & Banning', async () => {
  let strikeLogged = false;
  const attackerIp = '198.51.100.123';

  const guard = createPhinehasEdgeGuard({
    allowList: [], // Clear localhost
    logging: {
      enabled: false,
      onStrike: (strike) => {
        strikeLogged = true;
        assert.strictEqual(strike.ip, attackerIp);
        assert.strictEqual(strike.ruleMatched, 'rfc8615_wildcard');
      }
    }
  });

  // 1. Probe dotfile
  const attackReq = createMockNextRequest('/.env.production', {}, attackerIp);
  const result = await guard.check(attackReq);

  assert.strictEqual(result.isBlocked, true);
  assert.strictEqual(result.ruleMatched, 'rfc8615_wildcard');
  assert.strictEqual(strikeLogged, true);
  assert.ok(result.response);
  assert.strictEqual(result.response.status, 403);
  assert.strictEqual(result.response.headers.get('x-phinehas-verdict'), 'blocked');

  // 2. Subsequent request from same IP to clean route should be blocked by BanStore
  const cleanReq = createMockNextRequest('/api/profile', {}, attackerIp);
  const followUpResult = await guard.check(cleanReq);

  assert.strictEqual(followUpResult.isBlocked, true);
  assert.strictEqual(followUpResult.ruleMatched, 'explicit_trap');
  assert.ok(followUpResult.response);
  assert.strictEqual(followUpResult.response.status, 403);

  guard.close?.();
});

test('Next.js Edge Guard: Explicit Non-Dot Trap', async () => {
  const guard = createPhinehasEdgeGuard({
    allowList: [],
    logging: { enabled: false }
  });

  const req = createMockNextRequest('/_ignition/execute-solution', {}, '203.0.113.88');
  const result = await guard.check(req);

  assert.strictEqual(result.isBlocked, true);
  assert.strictEqual(result.ruleMatched, 'explicit_trap');
  assert.strictEqual(result.normalizedPath, '/_ignition/execute-solution');

  guard.close?.();
});

test('Next.js Edge Guard: AllowList & .well-known Exemption', async () => {
  const guard = createPhinehasEdgeGuard({
    allowList: ['127.0.0.1'],
    logging: { enabled: false }
  });

  // RFC 8615 .well-known route must never be blocked
  const wkReq = createMockNextRequest('/.well-known/jwks.json', {}, '198.51.100.99');
  const wkResult = await guard.check(wkReq);
  assert.strictEqual(wkResult.isBlocked, false);

  // Allowlisted IP probing dotfile must not be blocked
  const allowedReq = createMockNextRequest('/.env', {}, '127.0.0.1');
  const allowedResult = await guard.check(allowedReq);
  assert.strictEqual(allowedResult.isBlocked, false);

  guard.close?.();
});

test('Next.js Edge Guard: Fail-Open Resilience', async () => {
  // Guard with failing custom storage should fail open safely
  const brokenStore = {
    isBanned: async () => {
      throw new Error('KV Edge network timeout');
    },
    ban: async () => {
      throw new Error('KV Write failure');
    },
    unban: async () => {}
  };

  const guard = createPhinehasEdgeGuard({
    allowList: []
  });

  // Inject broken store
  (guard as any).store = brokenStore;

  const req = createMockNextRequest('/api/status', {}, '198.51.100.5');
  const result = await guard.check(req);

  // Must not throw and must fail-open
  assert.strictEqual(result.isBlocked, false);

  guard.close?.();
});
