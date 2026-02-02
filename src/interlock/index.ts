/**
 * InterLock Module Exports
 */

// Re-export from shared package
export { SignalTypes, BaNanoProtocol } from '@bop/interlock';
export type { Signal, SignalInput, RemoteInfo, InterlockConfig } from '@bop/interlock';

// Local signal types
export { FG_SIGNALS, STRING_TO_NUMERIC, NUMERIC_TO_STRING, getSignalType, getSignalName } from './signal-types.js';

// Legacy protocol exports (kept for compatibility)
export { encodeSignal, decodeSignal, createSignal, generateNonce, type Signal as LegacySignal } from './protocol.js';

// Tumbler filtering
export { configureTumbler, filterSignal, getTumblerConfig } from './tumbler.js';

// Handlers
export { registerHandler, handleSignal, registerDefaultHandlers, getRegisteredHandlers } from './handlers.js';

// Socket adapter
export {
  startInterlock,
  stopInterlock,
  sendSignal,
  broadcastSignal,
  getPeers,
  addPeer,
  removePeer,
  getStats
} from './socket.js';
