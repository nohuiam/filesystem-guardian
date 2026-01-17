#!/usr/bin/env node
/**
 * Filesystem Guardian MCP Server
 *
 * Extended attributes, Spotlight search, and filesystem event monitoring.
 *
 * Ports:
 * - MCP: stdio (stdin/stdout)
 * - InterLock: UDP 3026
 * - HTTP REST: 8026
 * - WebSocket: 9026
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from '@modelcontextprotocol/sdk/types.js';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Database
import { initDatabase, closeDatabase } from './database/schema.js';

// Tools
import { GET_XATTR_TOOL, handleGetXattr } from './tools/get-xattr.js';
import { SET_XATTR_TOOL, handleSetXattr } from './tools/set-xattr.js';
import { LIST_XATTR_TOOL, handleListXattr } from './tools/list-xattr.js';
import { SPOTLIGHT_SEARCH_TOOL, handleSpotlightSearch } from './tools/spotlight-search.js';
import { SPOTLIGHT_REINDEX_TOOL, handleSpotlightReindex } from './tools/spotlight-reindex.js';
import { WATCH_VOLUME_TOOL, handleWatchVolume } from './tools/watch-volume.js';

// Services
import { restoreWatches, stopAllWatches } from './services/fsevents-service.js';

// Servers
import { startHttpServer, stopHttpServer } from './http/server.js';
import { startWebSocketServer, stopWebSocketServer } from './websocket/server.js';
import { startInterlock, stopInterlock } from './interlock/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Load interlock config
function loadInterlockConfig() {
  try {
    const configPath = join(__dirname, '..', 'config', 'interlock.json');
    const content = readFileSync(configPath, 'utf-8');
    return JSON.parse(content);
  } catch {
    return null;
  }
}

// All tools (exported for HTTP gateway)
export const TOOLS = [
  GET_XATTR_TOOL,
  SET_XATTR_TOOL,
  LIST_XATTR_TOOL,
  SPOTLIGHT_SEARCH_TOOL,
  SPOTLIGHT_REINDEX_TOOL,
  WATCH_VOLUME_TOOL
];

// Tool handlers (exported for HTTP gateway)
export const TOOL_HANDLERS: Record<string, (args: unknown) => unknown | Promise<unknown>> = {
  get_xattr: handleGetXattr,
  set_xattr: handleSetXattr,
  list_xattr: handleListXattr,
  spotlight_search: handleSpotlightSearch,
  spotlight_reindex: handleSpotlightReindex,
  watch_volume: handleWatchVolume
};

async function main() {
  // Initialize database
  initDatabase();

  // Create MCP server
  const server = new Server(
    {
      name: 'filesystem-guardian',
      version: '1.0.0'
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  // List tools handler
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS
  }));

  // Call tool handler
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const handler = TOOL_HANDLERS[name];

    if (!handler) {
      return {
        content: [{ type: 'text', text: `Unknown tool: ${name}` }],
        isError: true
      };
    }

    try {
      const result = await handler(args);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return {
        content: [{ type: 'text', text: `Error: ${message}` }],
        isError: true
      };
    }
  });

  // Start auxiliary servers
  try {
    // Start HTTP server
    await startHttpServer();

    // Start WebSocket server
    await startWebSocketServer();

    // Start InterLock
    const interlockConfig = loadInterlockConfig();
    if (interlockConfig) {
      const peers = (interlockConfig.peers as string[]).map((name: string) => ({
        name,
        port: interlockConfig.peer_ports[name] || 3000,
        host: '127.0.0.1'
      }));

      await startInterlock({
        peers,
        signals: [...interlockConfig.signals.incoming, ...interlockConfig.signals.outgoing],
        sources: interlockConfig.peers
      });
    }

    // Restore watches from database
    restoreWatches();

    console.error('[filesystem-guardian] All servers started');
  } catch (error) {
    console.error('[filesystem-guardian] Failed to start auxiliary servers:', (error as Error).message);
  }

  // Graceful shutdown
  const shutdown = async () => {
    console.error('[filesystem-guardian] Shutting down...');

    stopAllWatches();
    await stopInterlock();
    await stopWebSocketServer();
    await stopHttpServer();
    closeDatabase();

    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  // Connect to stdio transport
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error('[filesystem-guardian] MCP server connected via stdio');
}

main().catch((error) => {
  console.error('[filesystem-guardian] Fatal error:', error);
  process.exit(1);
});
