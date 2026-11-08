# `@phinehas/nestjs`

> NestJS module and active-defense security middleware for enterprise Nest applications.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![NestJS](https://img.shields.io/badge/NestJS-10%2B-E0234E.svg)](https://nestjs.com/)

---

## Overview

`@phinehas/nestjs` wraps `@phinehas/node` and `@phinehas/core` into an idiomatic NestJS module and middleware. It intercepts automated vulnerability scanners, dotfile probes (`.env`, `.git`), and framework exploits before reaching NestJS controllers, severing TCP sockets immediately.

---

## Installation

```bash
yarn add @phinehas/nestjs @phinehas/node @phinehas/core
```

---

## Usage Patterns

### Pattern 1: Inline Middleware Configuration

The fastest way to protect all routes in your NestJS application:

```typescript
// app.module.ts
import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { PhinehasMiddleware } from '@phinehas/nestjs';

@Module({
  imports: [],
  controllers: [],
  providers: [],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(PhinehasMiddleware.configure({
        action: 'terminate', // Drop TCP socket immediately
        storage: { driver: 'memory', ttl: 3600 },
        logging: { format: 'structured' }
      }))
      .forRoutes('*');
  }
}
```

---

### Pattern 2: Dynamic Module (`PhinehasModule.forRoot`)

For centralized dependency injection across your NestJS application:

```typescript
// app.module.ts
import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { PhinehasModule, PhinehasMiddleware } from '@phinehas/nestjs';

@Module({
  imports: [
    PhinehasModule.forRoot({
      action: 'terminate',
      storage: { driver: 'memory', ttl: 3600 }
    })
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(PhinehasMiddleware)
      .forRoutes('*');
  }
}
```

---

### Pattern 3: Asynchronous Registration (`forRootAsync`)

When your Redis client or configuration options depend on `@nestjs/config`:

```typescript
// app.module.ts
import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PhinehasModule, PhinehasMiddleware } from '@phinehas/nestjs';
import Redis from 'ioredis';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    PhinehasModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        action: 'terminate',
        storage: {
          driver: 'redis',
          client: new Redis(config.getOrThrow<string>('REDIS_URL')),
          ttl: 86400 // 24-hour ban
        }
      })
    })
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(PhinehasMiddleware).forRoutes('*');
  }
}
```

---

## License

Apache-2.0. Maintained by [Phinehas HQ](https://github.com/phinehas-hq).
