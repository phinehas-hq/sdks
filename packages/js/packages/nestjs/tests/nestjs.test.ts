import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PhinehasMiddleware, PhinehasModule, PHINEHAS_OPTIONS } from '../src/index.ts';

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
  public socket: MockSocket;

  constructor(socket: MockSocket) {
    super();
    this.socket = socket;
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

test('NestJS Middleware: Static configure() method', async () => {
  const ConfiguredClass = PhinehasMiddleware.configure({
    action: 'terminate',
    allowList: [],
    logging: { enabled: false }
  });

  const middlewareInstance = new ConfiguredClass();
  assert.ok(typeof middlewareInstance.use === 'function');

  // 1. Attack path should sever socket
  const { req: attackReq, res: attackRes, socket: attackSocket } = createMockContext('/.env.backup', {}, '198.51.100.1');
  let attackNextCalled = false;
  await middlewareInstance.use(attackReq, attackRes, () => {
    attackNextCalled = true;
  });

  assert.strictEqual(attackNextCalled, false);
  assert.strictEqual(attackSocket.destroyed, true);

  // 2. Clean route should call next()
  const { req: cleanReq, res: cleanRes, socket: cleanSocket } = createMockContext('/api/cats', {}, '198.51.100.2');
  let cleanNextCalled = false;
  await middlewareInstance.use(cleanReq, cleanRes, () => {
    cleanNextCalled = true;
  });

  assert.strictEqual(cleanNextCalled, true);
  assert.strictEqual(cleanSocket.destroyed, false);
});

test('NestJS Module: Dynamic forRoot registration', () => {
  const dynamicModule = PhinehasModule.forRoot({
    action: 'reject',
    storage: { driver: 'memory', ttl: 1800 }
  });

  assert.strictEqual(dynamicModule.global, true);
  assert.ok(Array.isArray(dynamicModule.providers));
  assert.strictEqual(dynamicModule.providers.length, 2);

  // Check PHINEHAS_OPTIONS provider
  const optionsProvider = dynamicModule.providers.find((p) => p.provide === PHINEHAS_OPTIONS);
  assert.ok(optionsProvider);
  assert.strictEqual(optionsProvider.useValue.action, 'reject');
  assert.strictEqual(optionsProvider.useValue.storage.ttl, 1800);

  // Check PhinehasMiddleware factory provider
  const middlewareProvider = dynamicModule.providers.find((p) => p.provide === PhinehasMiddleware);
  assert.ok(middlewareProvider);
  assert.ok(typeof middlewareProvider.useFactory === 'function');

  const instance = middlewareProvider.useFactory(optionsProvider.useValue);
  assert.ok(instance instanceof PhinehasMiddleware);
});

test('NestJS Module: Dynamic forRootAsync registration', async () => {
  const dynamicModule = PhinehasModule.forRootAsync({
    useFactory: async () => ({
      action: 'terminate',
      storage: { driver: 'memory', ttl: 7200 }
    })
  });

  assert.strictEqual(dynamicModule.global, true);
  const optionsProvider = dynamicModule.providers?.find((p) => p.provide === PHINEHAS_OPTIONS);
  assert.ok(optionsProvider);
  assert.ok(typeof optionsProvider.useFactory === 'function');

  const resolvedOptions = await optionsProvider.useFactory();
  assert.strictEqual(resolvedOptions.action, 'terminate');
  assert.strictEqual(resolvedOptions.storage.ttl, 7200);
});
