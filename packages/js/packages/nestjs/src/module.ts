/**
 * Phinehas NestJS Dynamic Module
 */

import type { PhinehasOptions } from '../../core/src/index.ts';
import { PHINEHAS_OPTIONS } from './constants.ts';
import { PhinehasMiddleware } from './middleware.ts';

export interface DynamicModuleLike {
  module: any;
  providers?: any[];
  exports?: any[];
  global?: boolean;
}

export interface PhinehasModuleAsyncOptions {
  useFactory: (...args: any[]) => Promise<PhinehasOptions> | PhinehasOptions;
  inject?: any[];
}

export class PhinehasModule {
  /**
   * Registers the Phinehas module synchronously with static options.
   */
  public static forRoot(options: PhinehasOptions = {}): DynamicModuleLike {
    return {
      module: PhinehasModule,
      global: true,
      providers: [
        {
          provide: PHINEHAS_OPTIONS,
          useValue: options
        },
        {
          provide: PhinehasMiddleware,
          useFactory: (opts: PhinehasOptions) => new PhinehasMiddleware(opts),
          inject: [PHINEHAS_OPTIONS]
        }
      ],
      exports: [PHINEHAS_OPTIONS, PhinehasMiddleware]
    };
  }

  /**
   * Registers the Phinehas module asynchronously (e.g. via ConfigService).
   */
  public static forRootAsync(asyncOptions: PhinehasModuleAsyncOptions): DynamicModuleLike {
    return {
      module: PhinehasModule,
      global: true,
      providers: [
        {
          provide: PHINEHAS_OPTIONS,
          useFactory: asyncOptions.useFactory,
          inject: asyncOptions.inject || []
        },
        {
          provide: PhinehasMiddleware,
          useFactory: (opts: PhinehasOptions) => new PhinehasMiddleware(opts),
          inject: [PHINEHAS_OPTIONS]
        }
      ],
      exports: [PHINEHAS_OPTIONS, PhinehasMiddleware]
    };
  }
}
