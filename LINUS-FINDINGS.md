# Linus File Security Audit: filesystem-guardian

**Auditor:** Claude Code Instance 5
**Date:** 2026-01-07
**Branch:** linus-audit/filesystem-guardian

## File Security Summary
- Critical (Path Traversal): 3 issues - **FIXED**
- Major (File Safety): 1 issue - **FIXED**
- Minor (Code Quality): 0 issues

## Critical Issues

### 1. No Path Validation in xattr-service.ts
- **CWE:** CWE-22 (Path Traversal)
- **Location:** `src/services/xattr-service.ts` (all functions)
- **Attack:** Any path could be passed to `xattr` commands, allowing read/write/delete of extended attributes on any file
- **Fix:** Created `src/utils/path-validator.ts` and added `validatePath()` calls at entry of `listXattrs()`, `getXattrs()`, `setXattrs()`
- **Commit:** Part of audit branch

### 2. No Path Validation in spotlight-service.ts Scope
- **CWE:** CWE-22 (Path Traversal)
- **Location:** `src/services/spotlight-service.ts:29-39`
- **Attack:** Arbitrary directories could be passed as search scope to `mdfind`
- **Fix:** Added `validatePath()` for each scope directory, skip invalid ones with warning
- **Commit:** Part of audit branch

### 3. No Path Validation in spotlightReindex
- **CWE:** CWE-22 (Path Traversal)
- **Location:** `src/services/spotlight-service.ts:156`
- **Attack:** Could force Spotlight to reindex any path via `mdimport`
- **Fix:** Added `validatePath()` at function entry
- **Commit:** Part of audit branch

## Major Issues

### 4. Spotlight Results Not Filtered
- **CWE:** CWE-200 (Information Exposure)
- **Location:** `src/services/spotlight-service.ts:49`
- **Attack:** Search results could include paths outside sandbox
- **Fix:** Added `isPathAllowed()` filter on all results before returning
- **Commit:** Part of audit branch

## Files Created

| File | Purpose |
|------|---------|
| `src/utils/path-validator.ts` | Centralized path validation with sandbox enforcement, symlink rejection |

## Files Modified

| File | Changes |
|------|---------|
| `src/services/xattr-service.ts` | Added validatePath import and calls in listXattrs, getXattrs, setXattrs |
| `src/services/spotlight-service.ts` | Added path validation for scope, reindex path, and result filtering |

## Sandbox Configuration

```typescript
const ALLOWED_ROOTS = [
  '/Users/macbook/Documents/BoxOfPrompts-Central',
  '/Users/macbook/Documents/Dropository',
  '/Users/macbook/Documents/BoxOfPrompts-Central/Dropository'
];
```

## Security Features Implemented

1. **Null byte stripping** (CWE-158)
2. **URL decoding with double-encoding protection**
3. **Unicode NFC normalization**
4. **Symlink rejection** (CWE-59)
5. **Sandbox enforcement** via ALLOWED_ROOTS

## Build Status

TypeScript build succeeded after changes.

## Security Tests

**Location:** `tests/security/path-traversal.test.ts`, `tests/security/attribute-sanitization.test.ts`
**Result:** 64 tests passed

- [x] Path traversal vectors (`../`, URL-encoded, double-encoded, null byte)
- [x] Symlink rejection
- [x] Unicode normalization attacks
- [x] Input validation (null, undefined, empty, non-string)
- [x] Spotlight result filtering (via isPathAllowed)
- [x] xattr operations validation (via validatePath)
- [x] mdls attribute name sanitization (shell metacharacters, path chars)
- [x] Attribute pattern validation (alphanumeric + underscore only)

## Previously Remaining Concerns - NOW FIXED

1. ~~**execFile usage**: Using `promisify(execFile)` is safer than `exec`, but command outputs aren't validated~~
   - **Status:** Acceptable risk - mdfind outputs are filtered via `isPathAllowed()`, mdls attributes are validated via `sanitizeAttributes()`, xattr values are user data within sandbox

2. ~~**Error messages**: Some error messages may leak path information~~
   - **Status:** FIXED - Added `sanitizeErrorMessage()` function to `path-validator.ts` and applied to all error outputs in `spotlight-service.ts` and `xattr-service.ts`

## All Concerns Addressed

All critical, major, and low-risk concerns have been fixed or documented as acceptable risk.
