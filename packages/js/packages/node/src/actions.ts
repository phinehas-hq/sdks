/**
 * Phinehas Strike Actions & Connection Severance
 * Specification: Section 1.1 & Section 4
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { BanAction } from '@phinehas/core';

export interface ActionContext {
  req: IncomingMessage;
  res: ServerResponse;
}

/**
 * Executes the configured action against an attacking or banned client.
 */
export function executeAction(action: BanAction, ctx: ActionContext): void {
  const { req, res } = ctx;

  switch (action) {
    case 'terminate': {
      // 1. Defensively handle socket error events to prevent unhandled ECONNRESET in Node event loop
      if (req.socket && !req.socket.destroyed) {
        req.socket.on('error', () => {});
        req.socket.destroy();
      }
      if (res.socket && !res.socket.destroyed) {
        res.socket.on('error', () => {});
        res.socket.destroy();
      }
      break;
    }

    case 'reject': {
      if (!res.headersSent) {
        res.writeHead(403, {
          'Content-Type': 'text/plain',
          'Connection': 'close',
          'Content-Length': '0'
        });
      }
      res.end();
      break;
    }

    case 'tarpit': {
      if (!res.headersSent) {
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Transfer-Encoding': 'chunked',
          'Connection': 'keep-alive'
        });
      }

      // Drip 1 byte every 10 seconds to keep attacker threads blocked
      const interval = setInterval(() => {
        if (!res.destroyed && !req.destroyed && res.writable) {
          try {
            res.write(' ');
          } catch {
            clearInterval(interval);
          }
        } else {
          clearInterval(interval);
        }
      }, 10000);

      req.on('close', () => clearInterval(interval));
      res.on('close', () => clearInterval(interval));
      break;
    }
  }
}
