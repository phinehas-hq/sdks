/**
 * Anti-Bypass Path Normalization Pipeline
 * Specification: Section 6
 */

/**
 * Safely decodes percent-encoded characters in a raw URI path.
 * Handles single and multi-pass hex decodings (%2e, %2f, %5c).
 */
export function safeUrlDecode(rawPath: string): string {
  let decoded = rawPath;
  // Handle double or single percent encoding iteratively up to 3 passes
  for (let i = 0; i < 3; i++) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch {
      // If decodeURIComponent fails on invalid surrogate, replace known critical hex codes manually
      decoded = decoded
        .replace(/%2e/gi, '.')
        .replace(/%2f/gi, '/')
        .replace(/%5c/gi, '\\');
      break;
    }
  }
  return decoded;
}

/**
 * Resolves directory traversal segments (. and ..) without escaping root.
 */
export function resolvePathTraversal(pathStr: string): string {
  const parts = pathStr.split('/');
  const resolved: string[] = [];

  for (const part of parts) {
    if (part === '' || part === '.') {
      continue;
    }
    if (part === '..') {
      if (resolved.length > 0) {
        resolved.pop();
      }
    } else {
      resolved.push(part);
    }
  }

  return '/' + resolved.join('/');
}

/**
 * Executes the complete 6-stage anti-bypass normalization pipeline:
 * 1. Hex URL decoding (%2e, %2f, %5c)
 * 2. Backslash conversion (\ -> /)
 * 3. Slash collapsing (//+ -> /)
 * 4. Directory traversal resolution (/api/v1/../../.env -> /.env)
 * 5. Lowercasing
 * 6. Trailing slash removal
 */
export function normalizePath(rawPath: string): string {
  if (!rawPath || typeof rawPath !== 'string') {
    return '/';
  }

  // 1. URL Decoding
  let normalized = safeUrlDecode(rawPath);

  // 2. Windows Backslash Conversion
  normalized = normalized.replace(/\\+/g, '/');

  // Ensure leading slash
  if (!normalized.startsWith('/')) {
    normalized = '/' + normalized;
  }

  // 3. Slash Collapsing
  normalized = normalized.replace(/\/+/g, '/');

  // 4. Path Traversal Resolution
  normalized = resolvePathTraversal(normalized);

  // 5. Lowercasing
  normalized = normalized.toLowerCase();

  // 6. Trailing Slash Removal (preserve single root '/')
  if (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }

  return normalized;
}
