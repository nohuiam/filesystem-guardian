/**
 * Spotlight Service
 *
 * Provides Spotlight search and indexing using mdfind/mdimport.
 * All paths are validated against the sandbox before execution.
 */

import { execFile, spawn } from 'child_process';
import { promisify } from 'util';
import { stat } from 'fs/promises';
import { basename } from 'path';
import type { SpotlightResult, SpotlightSearchOutput, ReindexResult } from '../types.js';
import { validatePath, isPathAllowed, sanitizeErrorMessage } from '../utils/path-validator.js';

const exec = promisify(execFile);

/**
 * Valid Spotlight attribute name pattern
 * Attribute names must be alphanumeric with underscores, typically starting with kMDItem
 * Examples: kMDItemDisplayName, kMDItemContentType, kMDItemFSSize
 */
const VALID_ATTRIBUTE_PATTERN = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

/**
 * Sanitize and validate Spotlight attribute names
 * Prevents command injection via malicious attribute names
 */
function sanitizeAttributes(attrs: string[]): string[] {
  return attrs.filter(attr => {
    if (!attr || typeof attr !== 'string') return false;
    if (!VALID_ATTRIBUTE_PATTERN.test(attr)) {
      console.warn(`[spotlight] Rejecting invalid attribute name: ${attr}`);
      return false;
    }
    return true;
  });
}

/**
 * Search Spotlight index
 */
export async function spotlightSearch(
  query: string,
  scope?: string[],
  limit: number = 100,
  attributes?: string[]
): Promise<SpotlightSearchOutput> {
  const args: string[] = [];

  // SECURITY: Validate scope directories if provided
  if (scope && scope.length > 0) {
    for (const dir of scope) {
      try {
        const validatedDir = validatePath(dir);
        args.push('-onlyin', validatedDir);
      } catch {
        // SECURITY: Don't log actual path to prevent information leakage
        console.warn(`[spotlight] Skipping invalid scope directory`);
      }
    }
  }

  // Add the query
  args.push(query);

  try {
    const { stdout } = await exec('mdfind', args, { maxBuffer: 10 * 1024 * 1024 });
    const paths = stdout.trim().split('\n').filter(Boolean);

    // SECURITY: Filter results to only include paths within sandbox
    const allowedPaths = paths.filter(p => isPathAllowed(p));

    // Limit results
    const truncated = allowedPaths.length > limit;
    const limitedPaths = allowedPaths.slice(0, limit);

    // Get metadata for each result
    const results = await Promise.all(
      limitedPaths.map(p => getFileMetadata(p, attributes))
    );

    return {
      results: results.filter((r): r is SpotlightResult => r !== null),
      count: results.filter(r => r !== null).length,
      truncated
    };
  } catch (error) {
    // SECURITY: Sanitize error message to prevent path leakage
    throw new Error(`Spotlight search failed: ${sanitizeErrorMessage((error as Error).message)}`);
  }
}

/**
 * Get file metadata
 */
async function getFileMetadata(path: string, requestedAttrs?: string[]): Promise<SpotlightResult | null> {
  try {
    const stats = await stat(path);

    const result: SpotlightResult = {
      path,
      name: basename(path),
      kind: getFileKind(path),
      modified: stats.mtime.toISOString(),
      size: stats.size
    };

    // Get additional Spotlight attributes if requested
    if (requestedAttrs && requestedAttrs.length > 0) {
      const attrs = await getSpotlightAttributes(path, requestedAttrs);
      if (Object.keys(attrs).length > 0) {
        result.attributes = attrs;
      }
    }

    return result;
  } catch {
    return null;
  }
}

/**
 * Get Spotlight attributes for a file
 */
async function getSpotlightAttributes(path: string, attrs: string[]): Promise<Record<string, unknown>> {
  const result: Record<string, unknown> = {};

  // SECURITY: Sanitize attribute names to prevent command injection
  const safeAttrs = sanitizeAttributes(attrs);
  if (safeAttrs.length === 0) {
    return result;
  }

  try {
    const args = ['--name', ...safeAttrs, path];
    const { stdout } = await exec('mdls', args);

    // Parse mdls output
    const lines = stdout.split('\n');
    for (const line of lines) {
      const match = line.match(/^(\w+)\s+=\s+(.+)$/);
      if (match) {
        const [, name, value] = match;
        if (safeAttrs.includes(name)) {
          result[name] = parseSpotlightValue(value.trim());
        }
      }
    }
  } catch {
    // Ignore errors getting attributes
  }

  return result;
}

/**
 * Parse Spotlight attribute value
 */
function parseSpotlightValue(value: string): unknown {
  // Null value
  if (value === '(null)') return null;

  // Array
  if (value.startsWith('(') && value.endsWith(')')) {
    const inner = value.slice(1, -1).trim();
    if (!inner) return [];
    return inner.split(',').map(v => v.trim().replace(/^"|"$/g, ''));
  }

  // String
  if (value.startsWith('"') && value.endsWith('"')) {
    return value.slice(1, -1);
  }

  // Number
  const num = Number(value);
  if (!isNaN(num)) return num;

  return value;
}

/**
 * Force Spotlight to reindex a path
 */
export async function spotlightReindex(filePath: string): Promise<ReindexResult> {
  // SECURITY: Validate path is within sandbox
  let validatedPath: string;
  try {
    validatedPath = validatePath(filePath);
  } catch (error) {
    return {
      path: filePath,
      queued: false,
      message: `Path validation failed: ${(error as Error).message}`
    };
  }

  try {
    await exec('mdimport', [validatedPath]);
    return {
      path: validatedPath,
      queued: true,
      message: 'Reindex queued successfully'
    };
  } catch (error) {
    // SECURITY: Sanitize error message to prevent path leakage
    return {
      path: validatedPath,
      queued: false,
      message: `Reindex failed: ${sanitizeErrorMessage((error as Error).message)}`
    };
  }
}

/**
 * Get file kind based on extension
 */
function getFileKind(path: string): string {
  const ext = path.split('.').pop()?.toLowerCase() || '';

  const kinds: Record<string, string> = {
    md: 'Markdown Document',
    txt: 'Plain Text',
    pdf: 'PDF Document',
    doc: 'Word Document',
    docx: 'Word Document',
    xls: 'Excel Spreadsheet',
    xlsx: 'Excel Spreadsheet',
    ppt: 'PowerPoint',
    pptx: 'PowerPoint',
    jpg: 'JPEG Image',
    jpeg: 'JPEG Image',
    png: 'PNG Image',
    gif: 'GIF Image',
    mp3: 'MP3 Audio',
    mp4: 'MP4 Video',
    mov: 'QuickTime Movie',
    js: 'JavaScript',
    ts: 'TypeScript',
    json: 'JSON',
    html: 'HTML',
    css: 'CSS',
    py: 'Python Script',
    sh: 'Shell Script',
    zip: 'ZIP Archive',
    gz: 'Gzip Archive',
    tar: 'TAR Archive'
  };

  return kinds[ext] || 'Document';
}

/**
 * Common Spotlight query examples
 */
export const SpotlightQueries = {
  ALL_MARKDOWN: 'kMDItemDisplayName == "*.md"',
  RED_TAG: 'kMDItemUserTags == "Red"',
  RECENT_MODIFIED: 'kMDItemFSContentChangeDate >= $time.now(-7d)',
  PDF_FILES: 'kMDItemContentType == "com.adobe.pdf"',
  IMAGES: 'kMDItemContentTypeTree == "public.image"',
  TEXT_CONTENT: (text: string) => `kMDItemTextContent == "*${text}*"`
};
