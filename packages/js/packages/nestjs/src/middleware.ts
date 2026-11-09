/**
 * Phinehas NestJS Middleware Implementation
 * Specification: Section 5.2
 */

import { phinehas, type PhinehasMiddleware as NodeMiddleware } from '@phinehas/node';
import type { PhinehasOptions } from '@phinehas/core';

export interface NestMiddlewareLike {
  use(req: any, res: any, next: (error?: any) => void): any;
}

export type NestMiddlewareClass = new (...args: any[]) => NestMiddlewareLike;

export class PhinehasMiddleware implements NestMiddlewareLike {
  private readonly handler: NodeMiddleware;

  constructor(options?: PhinehasOptions) {
    this.handler = phinehas(options);
  }

  public use(req: any, res: any, next: (error?: any) => void): Promise<void> {
    return this.handler(req, res, next);
  }

  /**
   * Static factory enabling inline route configuration:
   * consumer.apply(PhinehasMiddleware.configure({ ... })).forRoutes('*')
   */
  public static configure(options: PhinehasOptions): NestMiddlewareClass {
    return class ConfiguredPhinehasMiddleware implements NestMiddlewareLike {
      private readonly handler: NodeMiddleware;

      constructor() {
        this.handler = phinehas(options);
      }

      public use(req: any, res: any, next: (error?: any) => void): Promise<void> {
        return this.handler(req, res, next);
      }
    };
  }
}
