/**
 * Path Validator
 * Security module for path validation and sandbox enforcement
 *
 * Addresses:
 * - CWE-22: Path Traversal
 * - CWE-59: Symlink Following
 * - CWE-158: Null Byte Injection
 */

import { lstatSync } from 'fs';
import path from 'path';

/**
 * Allowed root directories for file operations
 * All path operations are restricted to these directories
 */
export const ALLOWED_ROOTS = [
  '/Users/macbook/Documents/BoxOfPrompts-Central',
  '/Users/macbook/Documents/Dropository',
  '/Users/macbook/Documents/BoxOfPrompts-Central/Dropository'
];

/**
 * Validate and normalize a path, ensuring it's within the sandbox
 * @param filePath - Path to validate
 * @returns Normalized absolute path
 * @throws Error if path is outside sandbox, is a symlink, or invalid
 */
export function validatePath(filePath: string): string {
  if (!filePath || typeof filePath !== 'string') {
    throw new Error('Invalid path: must be a non-empty string');
  }

  // Strip null bytes (CWE-158)
  let sanitized = filePath.replace(/\0/g, '');

  // Normalize Unicode (NFC normalization)
  sanitized = sanitized.normalize('NFC');

  // Decode URL-encoded characters to catch traversal attempts
  // Handle double-encoding attacks (%252e = %2e = .)
  let decoded = sanitized;
  let prev = '';
  while (decoded !== prev) {
    prev = decoded;
    try {
      decoded = decodeURIComponent(decoded);
    } catch {
      break; // Invalid encoding, stop decoding
    }
  }

  // Resolve to absolute path (handles ../ internally)
  const absolute = path.resolve(decoded);

  // Re-normalize after resolution
  const normalized = path.normalize(absolute);

  // SECURITY: Reject symlinks (CWE-59)
  try {
    const stats = lstatSync(normalized);
    if (stats.isSymbolicLink()) {
      throw new Error('Symlinks are not allowed: potential sandbox escape');
    }
  } catch (err: any) {
    // ENOENT is ok - file doesn't exist yet
    if (err.code !== 'ENOENT') {
      // Re-throw symlink rejection
      if (err.message && err.message.includes('Symlinks are not allowed')) {
        throw err;
      }
      // Other errors are logged but not fatal (file might not exist yet)
    }
  }

  // Sandbox check - the definitive security gate
  const isAllowed = ALLOWED_ROOTS.some(root => {
    const normalizedRoot = path.normalize(root);
    return normalized === normalizedRoot ||
           normalized.startsWith(normalizedRoot + path.sep);
  });

  if (!isAllowed) {
    throw new Error('Path outside allowed directories');
  }

  return normalized;
}

/**
 * Check if a path is within the allowed sandbox
 * @param filePath - Path to check
 * @returns true if path is allowed, false otherwise
 */
export function isPathAllowed(filePath: string): boolean {
  try {
    validatePath(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate multiple paths
 * @param paths - Array of paths to validate
 * @returns Array of validated paths (invalid paths are filtered out)
 */
export function filterAllowedPaths(paths: string[]): string[] {
  return paths.filter(p => isPathAllowed(p));
}

/**
 * Sanitize error messages to prevent path information leakage
 * Removes any file paths from error messages to prevent exposing
 * information about files outside the sandbox
 * @param message - Error message to sanitize
 * @returns Sanitized error message
 */
export function sanitizeErrorMessage(message: string): string {
  if (!message || typeof message !== 'string') {
    return 'Unknown error';
  }

  // Pattern to match file paths (Unix-style)
  // Matches: /path/to/file, ./path, ../path
  const pathPattern = /(?:\/[\w\-._]+)+|\.\.?\/[\w\-._/]*/g;

  // Replace paths with generic placeholder
  let sanitized = message.replace(pathPattern, '[path]');

  // Also strip any remaining path-like patterns that might have escaped
  // Match patterns like "No such file or directory: /some/path"
  sanitized = sanitized.replace(/:\s*\[path\]/g, '');

  return sanitized;
}
