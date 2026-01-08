/**
 * Extended Attributes Service
 *
 * Provides xattr operations using macOS native commands.
 * All paths are validated against the sandbox before execution.
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import type { XattrResult, XattrValue, SetXattrResult, ListXattrResult, XattrEncoding } from '../types.js';
import { getDatabase } from '../database/schema.js';
import { validatePath } from '../utils/path-validator.js';

const exec = promisify(execFile);

/**
 * List all extended attributes on a file
 */
export async function listXattrs(filePath: string): Promise<ListXattrResult> {
  // SECURITY: Validate path is within sandbox
  const validatedPath = validatePath(filePath);

  const db = getDatabase();

  try {
    const { stdout } = await exec('xattr', [validatedPath]);
    const attributes = stdout.trim().split('\n').filter(Boolean);

    db.logXattrOperation('list', validatedPath, undefined, true);

    return {
      path: validatedPath,
      attributes,
      count: attributes.length
    };
  } catch (error) {
    db.logXattrOperation('list', validatedPath, undefined, false);
    const message = (error as Error).message;

    // No attributes is not an error
    if (message.includes('No such xattr')) {
      return { path: validatedPath, attributes: [], count: 0 };
    }

    throw new Error(`Failed to list xattrs: ${message}`);
  }
}

/**
 * Get extended attributes from a file
 */
export async function getXattrs(filePath: string, attribute?: string, decodePlist: boolean = true): Promise<XattrResult> {
  // SECURITY: Validate path is within sandbox
  const validatedPath = validatePath(filePath);

  const db = getDatabase();
  const attributes: Record<string, XattrValue> = {};

  try {
    // Get list of attributes first (already validates path)
    const { attributes: attrList } = await listXattrs(validatedPath);

    for (const attrName of attrList) {
      if (attribute && attrName !== attribute) continue;

      try {
        // Get attribute value using xattr -p
        const { stdout } = await exec('xattr', ['-p', attrName, validatedPath]);
        const rawValue = stdout.trim();

        // Determine encoding and decode
        const decoded = decodeXattrValue(rawValue, decodePlist);

        attributes[attrName] = decoded;
        db.logXattrOperation('get', validatedPath, attrName, true);
      } catch (err) {
        // Skip attributes we can't read
        console.error(`[filesystem-guardian] Failed to read ${attrName}: ${(err as Error).message}`);
      }
    }

    return {
      path: validatedPath,
      attributes,
      count: Object.keys(attributes).length
    };
  } catch (error) {
    db.logXattrOperation('get', validatedPath, attribute, false);
    throw error;
  }
}

/**
 * Set extended attributes on a file
 */
export async function setXattrs(
  filePath: string,
  attrs: Record<string, string | Record<string, unknown> | null>,
  createOnly: boolean = false
): Promise<SetXattrResult> {
  // SECURITY: Validate path is within sandbox
  const validatedPath = validatePath(filePath);

  const db = getDatabase();
  const set: string[] = [];
  const deleted: string[] = [];
  const failed: Array<{ name: string; error: string }> = [];

  // Check existing attributes if createOnly
  let existingAttrs: string[] = [];
  if (createOnly) {
    const result = await listXattrs(validatedPath);
    existingAttrs = result.attributes;
  }

  for (const [name, value] of Object.entries(attrs)) {
    try {
      if (value === null) {
        // Delete attribute
        await exec('xattr', ['-d', name, validatedPath]);
        deleted.push(name);
        db.logXattrOperation('delete', validatedPath, name, true);
      } else {
        // Check if exists when createOnly
        if (createOnly && existingAttrs.includes(name)) {
          failed.push({ name, error: 'Attribute already exists' });
          continue;
        }

        // Set attribute
        const valueStr = typeof value === 'object' ? JSON.stringify(value) : String(value);
        await exec('xattr', ['-w', name, valueStr, validatedPath]);
        set.push(name);
        db.logXattrOperation('set', validatedPath, name, true);
      }
    } catch (err) {
      failed.push({ name, error: (err as Error).message });
      db.logXattrOperation('set', validatedPath, name, false);
    }
  }

  return { path: validatedPath, set, deleted, failed };
}

/**
 * Decode an xattr value
 */
function decodeXattrValue(rawValue: string, decodePlist: boolean): XattrValue {
  // Check if it looks like hex-encoded data
  if (/^[0-9A-Fa-f\s]+$/.test(rawValue)) {
    const bytes = rawValue.replace(/\s/g, '');

    // Try to decode as UTF-8 string
    try {
      const buffer = Buffer.from(bytes, 'hex');
      const decoded = buffer.toString('utf8');

      // Check if it's valid UTF-8
      if (decoded && !decoded.includes('\ufffd')) {
        // Try to parse as JSON
        try {
          const parsed = JSON.parse(decoded);
          return {
            value: parsed,
            size: buffer.length,
            encoding: 'utf8'
          };
        } catch {
          return {
            value: decoded,
            size: buffer.length,
            encoding: 'utf8'
          };
        }
      }
    } catch {
      // Not valid UTF-8
    }

    // Return as hex
    return {
      value: bytes,
      size: bytes.length / 2,
      encoding: 'hex'
    };
  }

  // Plain string value
  try {
    const parsed = JSON.parse(rawValue);
    return {
      value: parsed,
      size: Buffer.byteLength(rawValue, 'utf8'),
      encoding: 'utf8'
    };
  } catch {
    return {
      value: rawValue,
      size: Buffer.byteLength(rawValue, 'utf8'),
      encoding: 'utf8'
    };
  }
}

/**
 * Common Apple extended attributes
 */
export const CommonAttributes = {
  FINDER_TAGS: 'com.apple.metadata:_kMDItemUserTags',
  FINDER_COMMENT: 'com.apple.metadata:kMDItemFinderComment',
  WHERE_FROM: 'com.apple.metadata:kMDItemWhereFroms',
  QUARANTINE: 'com.apple.quarantine',
  GLEC: 'com.imminence.glec',
  DEWEY: 'com.imminence.dewey',
  QM_REGISTRY: 'com.imminence.qm'
};
