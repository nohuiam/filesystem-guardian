/**
 * Attribute Sanitization Security Tests
 * Tests for command injection via mdls attribute names
 *
 * Linus Audit Instance 5
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';

/**
 * Valid Spotlight attribute name pattern (copied from spotlight-service.ts)
 */
const VALID_ATTRIBUTE_PATTERN = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

/**
 * Sanitize attributes (copied from spotlight-service.ts)
 */
function sanitizeAttributes(attrs: string[]): string[] {
  return attrs.filter(attr => {
    if (!attr || typeof attr !== 'string') return false;
    if (!VALID_ATTRIBUTE_PATTERN.test(attr)) return false;
    return true;
  });
}

// Command injection attack vectors
const INJECTION_VECTORS = [
  // Shell metacharacters
  'kMDItem; rm -rf /',
  'kMDItem`whoami`',
  'kMDItem$(cat /etc/passwd)',
  'kMDItem|ls',
  'kMDItem&& cat /etc/passwd',

  // Path traversal in attribute
  '../../../etc/passwd',
  '/etc/passwd',

  // Special characters
  'kMDItem"injection"',
  "kMDItem'injection'",
  'kMDItem\ninjection',
  'kMDItem\0null',

  // Spaces and control chars
  'kMDItem injection',
  'kMDItem\tinjection',

  // Unicode tricks
  'kMDItem\u0000null',
];

// Valid Spotlight attributes
const VALID_ATTRIBUTES = [
  'kMDItemDisplayName',
  'kMDItemContentType',
  'kMDItemFSSize',
  'kMDItemFSContentChangeDate',
  'kMDItemTextContent',
  'kMDItemUserTags',
  '_kMDItemPrivate',  // Underscore prefix is valid
  'customAttribute123',  // Custom attributes are valid
];

describe('Attribute Sanitization Security Tests', () => {

  describe('Injection Vector Rejection', () => {
    for (const vector of INJECTION_VECTORS) {
      it(`should reject malicious attribute: ${JSON.stringify(vector).slice(0, 40)}...`, () => {
        const result = sanitizeAttributes([vector]);
        assert.strictEqual(result.length, 0, `Should reject: ${vector}`);
      });
    }
  });

  describe('Valid Attribute Acceptance', () => {
    for (const attr of VALID_ATTRIBUTES) {
      it(`should accept valid attribute: ${attr}`, () => {
        const result = sanitizeAttributes([attr]);
        assert.strictEqual(result.length, 1);
        assert.strictEqual(result[0], attr);
      });
    }
  });

  describe('Mixed Input Handling', () => {
    it('should filter out invalid from mixed array', () => {
      const mixed = [
        'kMDItemDisplayName',
        'invalid; rm -rf /',
        'kMDItemFSSize',
        '../../../etc/passwd'
      ];
      const result = sanitizeAttributes(mixed);
      assert.strictEqual(result.length, 2);
      assert.deepStrictEqual(result, ['kMDItemDisplayName', 'kMDItemFSSize']);
    });

    it('should return empty array for all invalid', () => {
      const allInvalid = [
        'bad; command',
        '$(injection)',
        'path/traversal'
      ];
      const result = sanitizeAttributes(allInvalid);
      assert.strictEqual(result.length, 0);
    });
  });

  describe('Edge Cases', () => {
    it('should reject empty string', () => {
      const result = sanitizeAttributes(['']);
      assert.strictEqual(result.length, 0);
    });

    it('should reject null in array', () => {
      const result = sanitizeAttributes([null as any]);
      assert.strictEqual(result.length, 0);
    });

    it('should reject undefined in array', () => {
      const result = sanitizeAttributes([undefined as any]);
      assert.strictEqual(result.length, 0);
    });

    it('should reject numbers in array', () => {
      const result = sanitizeAttributes([123 as any]);
      assert.strictEqual(result.length, 0);
    });

    it('should handle empty array', () => {
      const result = sanitizeAttributes([]);
      assert.strictEqual(result.length, 0);
    });

    it('should reject attribute starting with number', () => {
      const result = sanitizeAttributes(['123kMDItem']);
      assert.strictEqual(result.length, 0);
    });

    it('should accept attribute starting with underscore', () => {
      const result = sanitizeAttributes(['_privateAttr']);
      assert.strictEqual(result.length, 1);
    });
  });

  describe('Pattern Validation', () => {
    it('should match standard kMDItem pattern', () => {
      assert.ok(VALID_ATTRIBUTE_PATTERN.test('kMDItemDisplayName'));
      assert.ok(VALID_ATTRIBUTE_PATTERN.test('kMDItemFSSize'));
    });

    it('should reject shell metacharacters', () => {
      assert.ok(!VALID_ATTRIBUTE_PATTERN.test('attr;cmd'));
      assert.ok(!VALID_ATTRIBUTE_PATTERN.test('attr|cmd'));
      assert.ok(!VALID_ATTRIBUTE_PATTERN.test('attr&cmd'));
      assert.ok(!VALID_ATTRIBUTE_PATTERN.test('$(cmd)'));
      assert.ok(!VALID_ATTRIBUTE_PATTERN.test('`cmd`'));
    });

    it('should reject whitespace', () => {
      assert.ok(!VALID_ATTRIBUTE_PATTERN.test('attr name'));
      assert.ok(!VALID_ATTRIBUTE_PATTERN.test('attr\tname'));
      assert.ok(!VALID_ATTRIBUTE_PATTERN.test('attr\nname'));
    });

    it('should reject path characters', () => {
      assert.ok(!VALID_ATTRIBUTE_PATTERN.test('path/to/attr'));
      assert.ok(!VALID_ATTRIBUTE_PATTERN.test('../attr'));
      assert.ok(!VALID_ATTRIBUTE_PATTERN.test('attr.sub'));
    });
  });
});
