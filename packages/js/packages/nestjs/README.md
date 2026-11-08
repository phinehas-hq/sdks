# `@phinehas/nestjs`

> Enterprise active-defense security module and middleware for NestJS applications.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../../../LICENSE)
[![NestJS](https://img.shields.io/badge/NestJS-10%2B-E0234E.svg)](https://nestjs.com/)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict-blue.svg)](https://www.typescriptlang.org/)
[![Compliance Parity](https://img.shields.io/badge/compliance-100%25-brightgreen.svg)](../../../../compliance/)

---

## 1. Overview & Architectural Placement

In NestJS, the HTTP request execution pipeline follows a strict sequence:
```
INCOMING HTTP REQUEST
  |
  +---> 1. NestJS Middleware (Phinehas executes here!) <--- TCP Socket Severed!
          |
          +---> 2. Guards (e.g. AuthGuard, RolesGuard)
                  |
                  +---> 3. Interceptors (pre-controller)
                          |
                          +---> 4. Pipes (e.g. ValidationPipe)
                                  |
                                  +---> 5. Controller Handler
```

**Why Middleware rather than a Guard?**
Guards and Interceptors execute *after* NestJS has performed route matching, instantiated dependency contexts, and allocated memory for the request. By executing at the NestJS **Middleware** boundary, `@phinehas/nestjs` intercepts reconnaissance crawlers (`.env`, `.git`, traversal, CMS probes) and severs the TCP socket immediately, saving your NestJS server from running expensive database queries, Passport auth strategies, or validation pipelines on malicious traffic.

---

## 2. Installation

Install using **Yarn**:
```bash
yarn add @phinehas/nestjs @phinehas/node @phinehas/core
# Optional Redis client for multi-pod Kubernetes clusters:
yarn add ioredis
```

---

## 3. Production Usage Patterns

### Pattern 1: Dynamic Module with Async Injection (`forRootAsync`)

**[PRODUCTION RECOMMENDED]** When options or your Redis connection are managed by `@nestjs/config`:

```typescript
// app.module.ts
import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PhinehasModule, PhinehasMiddleware } from '@phinehas/nestjs';
import Redis from 'ioredis';

@Module({
  imports: [
    // [REQUIRED] Global ConfigModule
    ConfigModule.forRoot({ isGlobal: true }),

    // =========================================================================
    // DYNAMIC ASYNC MODULE REGISTRATION (Required vs Optional Showcase)
    // =========================================================================
    PhinehasModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        // [OPTIONAL - DEFAULT: 'terminate']
        // 'terminate' (sever socket) | 'reject' (HTTP 403) | 'tarpit'
        action: config.get<'terminate' | 'reject' | 'tarpit'>('PHINEHAS_ACTION', 'terminate'),

        // [OPTIONAL - DEFAULT: in-process LRU with 3600s TTL]
        storage: {
          driver: config.get<string>('REDIS_URL') ? 'redis' : 'memory',
          client: config.get<string>('REDIS_URL')
            ? new Redis(config.getOrThrow<string>('REDIS_URL'))
            : undefined,
          ttl: config.get<number>('PHINEHAS_BAN_TTL', 86400), // 24-hour ban
          keyPrefix: 'phinehas:nest:ban:',
        },

        // [PRODUCTION RECOMMENDED - DEFAULT: false]
        proxy: {
          trust: config.get<boolean>('TRUST_PROXY', true),
          header: 'cf-connecting-ip', // Cloudflare / AWS ALB client IP
        },

        // [OPTIONAL - DEFAULT: ['127.0.0.1', '::1']]
        allowList: ['127.0.0.1', '::1'],

        // [OPTIONAL - DEFAULT: built-in traps + RFC 8615]
        honeypots: {
          custom: [/^\/admin-console(\/.*)?$/, '/api/v1/debug'],
          excludeDefaults: false,
        },

        // [OPTIONAL] Structured JSON logging
        logging: {
          format: 'structured',
          onStrike: (strike) => {
            console.warn(`[NESTJS SECURITY STRIKE] IP ${strike.ip} probed ${strike.path}`);
          },
        },
      }),
    }),
  ],
})
export class AppModule implements NestModule {
  // [REQUIRED] Apply the Phinehas middleware globally across all controller routes
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(PhinehasMiddleware).forRoutes('*');
  }
}
```

---

### Pattern 2: Static Module Registration (`forRoot`)

For straightforward applications with static configuration:

```typescript
// app.module.ts
import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { PhinehasModule, PhinehasMiddleware } from '@phinehas/nestjs';

@Module({
  imports: [
    PhinehasModule.forRoot({
      action: 'terminate',
      storage: { driver: 'memory', ttl: 86400 },
      proxy: { trust: true },
    }),
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(PhinehasMiddleware).forRoutes('*');
  }
}
```

---

## 4. End-to-End Testing with NestJS Test Module

You can verify that Phinehas properly guards your NestJS controllers using `@nestjs/testing`:

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { PhinehasModule } from '@phinehas/nestjs';

describe('AppController (e2e with Phinehas)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        // Override PhinehasModule with action: 'reject' for assertion ease
        PhinehasModule.forRoot({ action: 'reject' }),
        AppModule,
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it('/api/health (GET) -> 200 OK', () => {
    return request(app.getHttpServer())
      .get('/api/health')
      .expect(200);
  });

  it('/.well-known/security.txt (GET) -> Safe Pass (not 403)', () => {
    return request(app.getHttpServer())
      .get('/.well-known/security.txt')
      .expect((res) => {
        expect(res.status).not.toBe(403);
      });
  });

  it('/.env (GET) -> 403 Blocked by Phinehas', () => {
    return request(app.getHttpServer())
      .get('/.env')
      .expect(403);
  });
});
```

---

## 5. Navigation

* [Root SDK Documentation](../../../../README.md)
* [Core Engine Guide (`@phinehas/core`)](../core/README.md)
* [Node.js & Express Middleware (`@phinehas/node`)](../node/README.md)
* [Next.js Edge Guard (`@phinehas/next`)](../next/README.md)

---

## 6. License

Licensed under the [Apache-2.0 License](../../../../LICENSE). Maintained by [Phinehas HQ](https://github.com/phinehas-hq).
