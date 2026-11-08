import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { phinehas, extractClientIp, isIpAllowed } from '../src/index.ts';

class MockSocket extends EventEmitter {
  public destroyed = false;
  public remoteAddress: string;

  constructor(remoteAddress = '127.0.0.1') {
    super();
    this.remoteAddress = remoteAddress;
  }

  public destroy() {
    this.destroyed = true;
    this.emit('close');
  }
}

class MockResponse extends EventEmitter {
  public statusCode = 200;
  public headers: Record<string, string> = {};
  public body = '';
  public headersSent = false;
  public finished = false;
  public socket: MockSocket;

  constructor(socket: MockSocket) {
    super();
    this.socket = socket;
  }

  public writeHead(statusCode: number, headers?: Record<string, string>) {
    this.statusCode = statusCode;
    if (headers) {
      Object.assign(this.headers, headers);
    }
    this.headersSent = true;
  }

  public write(chunk: string) {
    this.body += chunk;
  }

  public end(data?: string) {
    if (data) this.body += data;
    this.finished = true;
    this.emit('finish');
  }
}

function createMockContext(url: string, headers: Record<string, string> = {}, remoteIp = '127.0.0.1') {
  const socket = new MockSocket(remoteIp);
  const req: any = {
    url,
    originalUrl: url,
    method: 'GET',
    headers: { ...headers },
    socket
  };
  const res = new MockResponse(socket);
  return { req, res, socket };
}

test('Node IP Extraction & AllowList Resolution', () => {
  // Direct socket IP without proxy trust
  const { req: directReq } = createMockContext('/', { 'x-forwarded-for': '1.2.3.4' }, '10.0.0.5');
  assert.strictEqual(extractClientIp(directReq), '10.0.0.5');

  // Proxy trusted with custom cloud header (Cloudflare)
  const { req: cfReq } = createMockContext(
    '/',
    { 'cf-connecting-ip': '203.0.113.195', 'x-forwarded-for': '10.0.0.1' },
    '10.0.0.5'
  );
  assert.strictEqual(
    extractClientIp(cfReq, { trust: true, header: 'cf-connecting-ip' }),
    '203.0.113.195'
  );

  // X-Forwarded-For chain with depth resolution
  const { req: xffReq } = createMockContext(
    '/',
    { 'x-forwarded-for': '198.51.100.1, 10.0.0.2, 10.0.0.3' },
    '10.0.0.5'
  );
  // depth 1: rightmost hop before proxy -> 10.0.0.3
  assert.strictEqual(extractClientIp(xffReq, { trust: true, depth: 1 }), '10.0.0.3');
  // default: client (leftmost) -> 198.51.100.1
  assert.strictEqual(extractClientIp(xffReq, { trust: true }), '198.51.100.1');

  // Allowlist checks
  assert.strictEqual(isIpAllowed('127.0.0.1', ['127.0.0.1', '::1']), true);
  assert.strictEqual(isIpAllowed('::ffff:127.0.0.1', ['127.0.0.1']), true);
  assert.strictEqual(isIpAllowed('192.168.1.1', ['127.0.0.1', '::1']), false);
});

test('Node Middleware: Clean Route Pass-Through', async () => {
  const middleware = phinehas();
  const { req, res } = createMockContext('/api/v1/health');

  let nextCalled = false;
  await middleware(req, res as any, () => {
    nextCalled = true;
  });

  assert.strictEqual(nextCalled, true, 'Clean route must yield to next()');
  assert.strictEqual(res.socket.destroyed, false);
});

test('Node Middleware: Immediate Socket Severance (Action: terminate)', async () => {
  let strikeLogged = false;
  const attackerIp = '198.51.100.77';

  const middleware = phinehas({
    action: 'terminate',
    allowList: [], // Clear localhost exemption
    proxy: { trust: true, header: 'cf-connecting-ip' },
    logging: {
      enabled: false,
      onStrike: (strike) => {
        strikeLogged = true;
        assert.strictEqual(strike.ip, attackerIp);
        assert.strictEqual(strike.ruleMatched, 'rfc8615_wildcard');
      }
    }
  });

  const { req, res, socket } = createMockContext('/.env', { 'cf-connecting-ip': attackerIp });

  let nextCalled = false;
  await middleware(req, res as any, () => {
    nextCalled = true;
  });

  assert.strictEqual(nextCalled, false, 'next() must NOT be called on attack');
  assert.strictEqual(socket.destroyed, true, 'Socket must be severed immediately on attack');
  assert.strictEqual(strikeLogged, true, 'Strike event must be emitted');

  // Subsequent request from now-banned IP to clean route should also be immediately severed!
  const { req: followUpReq, res: followUpRes, socket: followUpSocket } = createMockContext(
    '/api/v1/status',
    { 'cf-connecting-ip': attackerIp }
  );

  let followUpNextCalled = false;
  await middleware(followUpReq, followUpRes as any, () => {
    followUpNextCalled = true;
  });

  assert.strictEqual(followUpNextCalled, false);
  assert.strictEqual(followUpSocket.destroyed, true, 'Subsequent request from banned IP must be severed');
});

test('Node Middleware: HTTP 403 Rejection (Action: reject)', async () => {
  const attackerIp = '203.0.113.44';

  const middleware = phinehas({
    action: 'reject',
    allowList: [],
    proxy: { trust: true, header: 'cf-connecting-ip' },
    logging: { enabled: false }
  });

  const { req, res, socket } = createMockContext('/wp-login.php', { 'cf-connecting-ip': attackerIp });

  let nextCalled = false;
  await middleware(req, res as any, () => {
    nextCalled = true;
  });

  assert.strictEqual(nextCalled, false);
  assert.strictEqual(socket.destroyed, false, 'Socket should not be abruptly destroyed in reject mode');
  assert.strictEqual(res.statusCode, 403);
  assert.strictEqual(res.finished, true);
  assert.strictEqual(res.headers['Content-Length'], '0');
});

test('Node Middleware: AllowList Exemption & RFC 8615 Pass-Through', async () => {
  const middleware = phinehas({
    allowList: ['127.0.0.1'],
    logging: { enabled: false }
  });

  // 1. RFC 8615 .well-known request must pass cleanly
  const { req: wkReq, res: wkRes } = createMockContext('/.well-known/acme-challenge/test');
  let wkNextCalled = false;
  await middleware(wkReq, wkRes as any, () => {
    wkNextCalled = true;
  });
  assert.strictEqual(wkNextCalled, true);
  assert.strictEqual(wkRes.socket.destroyed, false);

  // 2. Allowlisted IP probing dotfile should pass without being banned or severed
  const { req: allowedReq, res: allowedRes } = createMockContext('/.env', {}, '127.0.0.1');
  let allowedNextCalled = false;
  await middleware(allowedReq, allowedRes as any, () => {
    allowedNextCalled = true;
  });
  assert.strictEqual(allowedNextCalled, true, 'Allowlisted IP must bypass checks');
  assert.strictEqual(allowedRes.socket.destroyed, false);
});
