/**
 * Filesystem Guardian Signal Types
 * Domain-specific signals in 0x70-0x7F range
 */

import { SignalTypes } from '@bop/interlock';

// Re-export standard signal types
export { SignalTypes };

// Domain-specific signals for filesystem-guardian
export const FG_SIGNALS = {
  // Xattr operations
  XATTR_QUERY: 0x70,
  XATTR_LIST: 0x71,
  XATTR_QUERY_RESPONSE: 0x72,
  XATTR_LIST_RESPONSE: 0x73,

  // Spotlight operations
  SPOTLIGHT_QUERY: 0x74,
  SPOTLIGHT_QUERY_RESPONSE: 0x75,
  SPOTLIGHT_INDEXED: 0x76,

  // Watch operations
  WATCH_LIST: 0x77,
  WATCH_LIST_RESPONSE: 0x78,
  FS_WATCH_EVENT: 0x79,

  // File metadata
  FILE_METADATA_REQUEST: 0x7A,
  FILE_METADATA_RESPONSE: 0x7B,

  // Status
  STATUS_REQUEST: 0x7C,
  STATUS_RESPONSE: 0x7D,

  // Xattr updates
  FS_XATTR_UPDATED: 0x7E,
} as const;

export type FGSignalType = (typeof FG_SIGNALS)[keyof typeof FG_SIGNALS];

// String-to-numeric mapping for backward compatibility
export const STRING_TO_NUMERIC: Record<string, number> = {
  'ping': SignalTypes.PING,
  'pong': SignalTypes.PONG,
  'heartbeat': SignalTypes.HEARTBEAT,
  'announce': SignalTypes.DOCK_REQUEST,
  'departure': SignalTypes.DISCONNECT,
  'status_request': FG_SIGNALS.STATUS_REQUEST,
  'xattr_query': FG_SIGNALS.XATTR_QUERY,
  'xattr_list': FG_SIGNALS.XATTR_LIST,
  'spotlight_query': FG_SIGNALS.SPOTLIGHT_QUERY,
  'watch_list': FG_SIGNALS.WATCH_LIST,
  'file_metadata_request': FG_SIGNALS.FILE_METADATA_REQUEST,
};

// Numeric-to-string mapping for responses
export const NUMERIC_TO_STRING: Record<number, string> = Object.fromEntries(
  Object.entries(STRING_TO_NUMERIC).map(([k, v]) => [v, k])
);

export function getSignalType(stringType: string): number {
  return STRING_TO_NUMERIC[stringType] ?? SignalTypes.PING;
}

export function getSignalName(numericType: number): string {
  return NUMERIC_TO_STRING[numericType] ?? `unknown_0x${numericType.toString(16)}`;
}
