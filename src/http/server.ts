/**
 * Filesystem Guardian HTTP REST API
 * Port: 8026
 */

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { randomUUID } from 'crypto';
import { getXattrs, setXattrs, listXattrs } from '../services/xattr-service.js';
import { spotlightSearch, spotlightReindex } from '../services/spotlight-service.js';
import { createWatch, stopWatch, getActiveWatches } from '../services/fsevents-service.js';
import { getRecentOperations, getDatabase } from '../database/schema.js';
import type { FsEventType } from '../types.js';
import { TOOLS, TOOL_HANDLERS } from '../index.js';

const PORT = 8026;

// In-memory rate limiting (Linus audit compliance)
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX = 100;

interface RouteHandler {
  (req: IncomingMessage, res: ServerResponse, body: string): Promise<void>;
}

const routes: Record<string, Record<string, RouteHandler>> = {
  GET: {
    '/health': async (_req, res) => {
      sendJson(res, 200, {
        status: 'healthy',
        server: 'filesystem-guardian',
        timestamp: new Date().toISOString(),
        ports: { http: 8026, ws: 9026, udp: 3026 }
      });
    },

    '/health/ready': async (_req, res) => {
      try {
        const db = getDatabase();
        // If we can get database, we're ready
        sendJson(res, 200, {
          ready: true,
          server: 'filesystem-guardian',
          checks: {
            database: true
          }
        });
      } catch (error) {
        sendJson(res, 503, {
          ready: false,
          server: 'filesystem-guardian',
          checks: {
            database: false
          },
          error: 'Database not ready'
        });
      }
    },

    '/api/watches': async (_req, res) => {
      const watches = getActiveWatches();
      sendJson(res, 200, { watches });
    },

    '/api/operations': async (_req, res) => {
      const operations = getRecentOperations(100);
      sendJson(res, 200, { operations });
    },

    '/api/tools': async (_req, res) => {
      const toolList = TOOLS.map(t => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema
      }));
      sendJson(res, 200, { tools: toolList, count: toolList.length });
    }
  },

  POST: {
    '/api/xattr/get': async (_req, res, body) => {
      const { path, names } = JSON.parse(body);
      const result = await getXattrs(path, names);
      sendJson(res, 200, result);
    },

    '/api/xattr/set': async (_req, res, body) => {
      const { path, attributes, create_only } = JSON.parse(body);
      const result = await setXattrs(path, attributes, create_only ?? false);
      sendJson(res, 200, result);
    },

    '/api/xattr/list': async (_req, res, body) => {
      const { path } = JSON.parse(body);
      const result = await listXattrs(path);
      sendJson(res, 200, result);
    },

    '/api/spotlight/search': async (_req, res, body) => {
      const { query, scope, limit, attributes } = JSON.parse(body);
      const result = await spotlightSearch(query, scope, limit ?? 100, attributes);
      sendJson(res, 200, result);
    },

    '/api/spotlight/reindex': async (_req, res, body) => {
      const { path } = JSON.parse(body);
      const result = await spotlightReindex(path);
      sendJson(res, 200, result);
    },

    '/api/watch/start': async (_req, res, body) => {
      const { path, events, recursive } = JSON.parse(body);
      const eventTypes = (events || ['created', 'modified', 'deleted', 'renamed']) as FsEventType[];
      const result = createWatch(path, eventTypes, recursive ?? true);
      sendJson(res, 200, result);
    },

    '/api/watch/stop': async (_req, res, body) => {
      const { watch_id } = JSON.parse(body);
      const success = stopWatch(watch_id);
      sendJson(res, 200, { success, watch_id });
    }
  }
};

function sendJson(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function parseBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const method = req.method || 'GET';
  const url = req.url || '/';

  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Request-ID');

  // Request ID tracing (Linus audit compliance)
  const requestId = (req.headers['x-request-id'] as string) || randomUUID();
  res.setHeader('X-Request-ID', requestId);

  if (method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Rate limiting (Linus audit compliance) - skip for health checks
  if (!url.startsWith('/health')) {
    const clientIp = req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const entry = rateLimitMap.get(clientIp);

    if (!entry || now > entry.resetTime) {
      rateLimitMap.set(clientIp, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    } else if (entry.count >= RATE_LIMIT_MAX) {
      sendJson(res, 429, { error: 'Too many requests', retryAfter: Math.ceil((entry.resetTime - now) / 1000) });
      return;
    } else {
      entry.count++;
    }
  }

  try {
    const body = method === 'POST' ? await parseBody(req) : '';
    const handler = routes[method]?.[url];

    if (handler) {
      await handler(req, res, body);
    } else if (method === 'POST' && url.startsWith('/api/tools/')) {
      // Handle dynamic tool execution route
      const toolName = url.replace('/api/tools/', '');
      const toolHandler = TOOL_HANDLERS[toolName];

      if (!toolHandler) {
        sendJson(res, 404, { success: false, error: `Tool '${toolName}' not found` });
        return;
      }

      const parsedBody = JSON.parse(body || '{}');
      const args = parsedBody.arguments || parsedBody;
      const result = await toolHandler(args);
      sendJson(res, 200, { success: true, result });
    } else {
      sendJson(res, 404, { error: 'Not found' });
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    sendJson(res, 500, { error: message });
  }
}

let server: ReturnType<typeof createServer> | null = null;

export function startHttpServer(): Promise<void> {
  return new Promise((resolve, reject) => {
    server = createServer(handleRequest);
    server.on('error', reject);
    server.listen(PORT, () => {
      console.error(`[filesystem-guardian] HTTP server listening on port ${PORT}`);
      resolve();
    });
  });
}

export function stopHttpServer(): Promise<void> {
  return new Promise((resolve) => {
    if (server) {
      server.close(() => resolve());
    } else {
      resolve();
    }
  });
}
