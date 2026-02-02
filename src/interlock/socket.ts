/**
 * InterLock Socket Adapter
 * Wraps @bop/interlock InterlockSocket while maintaining existing functional API
 */

import { InterlockSocket, SignalTypes } from '@bop/interlock';
import type { Signal, SignalInput, RemoteInfo, InterlockConfig } from '@bop/interlock';
import { STRING_TO_NUMERIC, getSignalName, FG_SIGNALS } from './signal-types.js';
import { filterSignal, configureTumbler } from './tumbler.js';
import { handleSignal, registerDefaultHandlers } from './handlers.js';

const SERVER_ID = 'filesystem-guardian';
const PORT = 3026;

interface Peer {
  name: string;
  port: number;
  host: string;
}

let socket: InterlockSocket | null = null;
let heartbeatTimer: NodeJS.Timeout | null = null;

/**
 * Create a signal object for the shared package
 */
function createSignal(type: number, payload: Record<string, unknown>): SignalInput {
  return {
    type,
    data: {
      serverId: SERVER_ID,
      ...payload,
    },
  };
}

/**
 * Send a signal to a specific peer
 */
export function sendSignal(type: number, payload: Record<string, unknown>, peer: Peer): void {
  if (!socket) return;

  const signal = createSignal(type, payload);
  socket.send(peer.host, peer.port, signal).catch((err) => {
    console.error(`[filesystem-guardian] Failed to send to ${peer.name}:`, err.message);
  });
}

/**
 * Broadcast a signal to all peers (string type for backward compat)
 */
export function broadcastSignal(type: string, payload: Record<string, unknown>): void {
  if (!socket) return;

  const numericType = STRING_TO_NUMERIC[type] ?? SignalTypes.PING;
  const signal = createSignal(numericType, payload);
  socket.broadcast(signal).catch((err) => {
    console.error('[filesystem-guardian] Broadcast error:', err.message);
  });
}

/**
 * Start the InterLock UDP socket
 */
export function startInterlock(config: { peers: Peer[]; signals: string[]; sources: string[] }): Promise<void> {
  return new Promise(async (resolve, reject) => {
    // Configure tumbler
    configureTumbler(config.signals, config.sources);

    // Register handlers
    registerDefaultHandlers();

    // Build peers map for shared package
    const peers: Record<string, { host: string; port: number }> = {};
    for (const peer of config.peers) {
      peers[peer.name] = { host: peer.host, port: peer.port };
    }

    // Create shared socket
    const socketConfig: InterlockConfig = {
      port: PORT,
      serverId: SERVER_ID,
      heartbeat: {
        interval: 30000,
        timeout: 90000,
      },
      peers,
    };

    socket = new InterlockSocket(socketConfig);

    socket.on('error', (err) => {
      console.error(`[filesystem-guardian] InterLock error:`, err.message);
    });

    socket.on('signal', async (signal: Signal, rinfo: RemoteInfo) => {
      // Convert to legacy format for handlers
      const legacySignal = {
        type: getSignalName(signal.type as number),
        source: signal.data.serverId,
        payload: signal.data,
        timestamp: signal.timestamp,
        nonce: `${signal.timestamp}-auto`,
      };

      // Apply tumbler filter
      if (!filterSignal(legacySignal)) {
        console.error(`[filesystem-guardian] Signal filtered: ${legacySignal.type} from ${legacySignal.source}`);
        return;
      }

      // Handle the signal
      const response = await handleSignal(legacySignal);
      if (response) {
        sendResponse(signal, response, rinfo);
      }
    });

    try {
      await socket.start();
      console.error(`[filesystem-guardian] InterLock listening on port ${PORT}`);

      // Announce presence to peers
      broadcastSignal('announce', {
        server: SERVER_ID,
        port: PORT,
        capabilities: ['xattr', 'spotlight', 'fsevents'],
      });

      // Start heartbeat timer
      heartbeatTimer = setInterval(() => {
        broadcastSignal('heartbeat', {
          server: SERVER_ID,
          status: 'healthy',
          uptime: process.uptime(),
        });
      }, 30000);

      // Send initial heartbeat
      broadcastSignal('heartbeat', {
        server: SERVER_ID,
        status: 'healthy',
        uptime: process.uptime(),
      });

      resolve();
    } catch (err) {
      reject(err);
    }
  });
}

/**
 * Send a response signal
 */
function sendResponse(originalSignal: Signal, response: Record<string, unknown>, rinfo: RemoteInfo): void {
  if (!socket) return;

  const responseType = (originalSignal.type as number) + 1; // Convention: response = request + 1
  const signal = createSignal(responseType, {
    ...response,
    target: originalSignal.data.serverId,
  });

  socket.send(rinfo.address, rinfo.port, signal).catch((err) => {
    console.error('[filesystem-guardian] Response send error:', err.message);
  });
}

/**
 * Stop the InterLock socket
 */
export function stopInterlock(): Promise<void> {
  return new Promise(async (resolve) => {
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer);
      heartbeatTimer = null;
    }

    if (socket) {
      // Send departure signal
      broadcastSignal('departure', {
        server: SERVER_ID,
      });

      await socket.stop();
      socket = null;
    }

    resolve();
  });
}

/**
 * Get peer list
 */
export function getPeers(): Peer[] {
  if (!socket) return [];
  const stats = socket.getStats();
  return stats.peers.map((p) => ({
    name: p.serverId,
    host: p.endpoint.split(':')[0],
    port: parseInt(p.endpoint.split(':')[1], 10),
  }));
}

/**
 * Add a peer dynamically
 */
export function addPeer(peer: Peer): void {
  if (socket) {
    socket.addPeer(peer.name, peer.host, peer.port);
  }
}

/**
 * Remove a peer
 */
export function removePeer(name: string): void {
  if (socket) {
    socket.removePeer(name);
  }
}

/**
 * Get socket stats
 */
export function getStats() {
  if (!socket) return null;
  return socket.getStats();
}
