/**
 * Default Explicit Non-Dot Traps Registry
 * Specification: Section 2.2
 */

export const DEFAULT_EXPLICIT_TRAPS: readonly string[] = [
  // CMS & Common Admin Consoles
  '/wp-login.php',
  '/wp-admin',
  '/xmlrpc.php',
  '/wp-config.php',
  '/administrator',
  '/user/login',

  // Database Management Consoles
  '/phpmyadmin',
  '/pma',
  '/adminer.php',
  '/mysql',
  '/dbadmin',

  // Framework Debuggers & Sensitive Endpoints
  '/_ignition/execute-solution',
  '/__debug__',
  '/actuator',
  '/actuator/env',
  '/actuator/health',
  '/telescope',
  '/elmah.axd',

  // Sensitive File Dumps & Archives
  '/dump.sql',
  '/backup.sql',
  '/database.sql',
  '/db.sqlite3',
  '/backup.tar.gz',
  '/backup.zip'
] as const;

/**
 * RFC 8615-Compliant Wildcard Detection Pattern
 * Negative lookahead ensures standard .well-known routes are never trapped.
 */
export const RFC8615_PATTERN = /^\/\.(?!well-known(\/|$))[a-zA-Z0-9_\-\.]+/;
