import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import {
  normalizePath,
  ThreatEvaluator,
  MemoryStore,
  PhinehasLogger,
  DEFAULT_EXPLICIT_TRAPS
} from '../src/index.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const complianceDir = resolve(__dirname, '../../../../../compliance');

test('Anti-Bypass Path Normalization Compliance', () => {
  const rawJson = readFileSync(resolve(complianceDir, 'normalization_vectors.json'), 'utf-8');
  const fixture = JSON.parse(rawJson);

  for (const tc of fixture.cases) {
    const actual = normalizePath(tc.raw_input);
    assert.strictEqual(
      actual,
      tc.expected_normalized,
      `Normalization failed for [${tc.raw_input}]: expected ${tc.expected_normalized}, got ${actual}`
    );
  }
});

test('RFC 8615 Wildcard Rule Compliance', () => {
  const rawJson = readFileSync(resolve(complianceDir, 'rfc8615_vectors.json'), 'utf-8');
  const fixture = JSON.parse(rawJson);
  const evaluator = new ThreatEvaluator();

  for (const tc of fixture.cases) {
    const result = evaluator.evaluate(tc.path);
    assert.strictEqual(
      result.isBlocked,
      tc.expected_strike,
      `RFC 8615 test failed for [${tc.path}] (${tc.reason}): expected isBlocked=${tc.expected_strike}, got ${result.isBlocked}`
    );

    if (tc.expected_strike) {
      assert.strictEqual(result.ruleMatched, 'rfc8615_wildcard');
    }
  }
});

test('Explicit Traps Registry Compliance', () => {
  const rawJson = readFileSync(resolve(complianceDir, 'explicit_traps.json'), 'utf-8');
  const fixture = JSON.parse(rawJson);
  const evaluator = new ThreatEvaluator();

  for (const trapPath of fixture.traps) {
    const result = evaluator.evaluate(trapPath);
    assert.strictEqual(
      result.isBlocked,
      true,
      `Explicit trap failed for [${trapPath}]: expected to be blocked`
    );
    assert.strictEqual(result.ruleMatched, 'explicit_trap');
  }

  // Verify prefix matching (e.g. /wp-admin/install.php, /actuator/prometheus)
  const prefixCases = [
    '/wp-admin/install.php',
    '/wp-admin/includes/file.php',
    '/actuator/env',
    '/actuator/metrics',
    '/phpmyadmin/index.php'
  ];

  for (const p of prefixCases) {
    const res = evaluator.evaluate(p);
    assert.strictEqual(res.isBlocked, true, `Prefix trap failed for [${p}]`);
    assert.strictEqual(res.ruleMatched, 'explicit_trap');
  }
});

test('Custom Traps & Exclude Defaults Option', () => {
  const customEvaluator = new ThreatEvaluator({
    custom: ['/api/internal/debug', '/honeypot.json'],
    excludeDefaults: true
  });

  // Custom paths must be trapped
  assert.strictEqual(customEvaluator.evaluate('/api/internal/debug').isBlocked, true);
  assert.strictEqual(customEvaluator.evaluate('/honeypot.json').isBlocked, true);
  assert.strictEqual(customEvaluator.evaluate('/api/internal/debug').ruleMatched, 'custom_trap');

  // Standard non-dot traps must be ignored when excludeDefaults is true
  assert.strictEqual(customEvaluator.evaluate('/wp-login.php').isBlocked, false);

  // RFC 8615 dotfiles MUST STILL BE TRAPPED (security baseline)
  assert.strictEqual(customEvaluator.evaluate('/.env').isBlocked, true);
});

test('MemoryStore: LRU Eviction, TTL Expiration, and Capacity Cap', () => {
  // Cap at 3 entries with 1 second TTL for testing
  const store = new MemoryStore({ maxCapacity: 3, defaultTtlSeconds: 1 });

  store.ban('1.1.1.1');
  store.ban('2.2.2.2');
  store.ban('3.3.3.3');

  assert.strictEqual(store.size, 3);
  assert.strictEqual(store.isBanned('1.1.1.1'), true);
  assert.strictEqual(store.isBanned('2.2.2.2'), true);
  assert.strictEqual(store.isBanned('3.3.3.3'), true);

  // Access 1.1.1.1 so it moves to head, making 2.2.2.2 the least recently used
  store.isBanned('1.1.1.1');

  // Insert 4th IP -> should evict 2.2.2.2
  store.ban('4.4.4.4');
  assert.strictEqual(store.size, 3);
  assert.strictEqual(store.isBanned('2.2.2.2'), false);
  assert.strictEqual(store.isBanned('1.1.1.1'), true);
  assert.strictEqual(store.isBanned('4.4.4.4'), true);

  // Test unban
  store.unban('4.4.4.4');
  assert.strictEqual(store.isBanned('4.4.4.4'), false);
  assert.strictEqual(store.size, 2);

  // Test permanent ban (ttl: 0)
  store.ban('5.5.5.5', 0);
  assert.strictEqual(store.isBanned('5.5.5.5'), true);

  store.close();
  assert.strictEqual(store.size, 0);
});

test('Structured Logger Verification', () => {
  const logged: string[] = [];
  const originalWarn = console.warn;
  console.warn = (msg: string) => logged.push(msg);

  let callbackCalled = false;
  const logger = new PhinehasLogger({
    enabled: true,
    format: 'structured',
    onStrike: (strike) => {
      callbackCalled = true;
      assert.strictEqual(strike.ip, '1.2.3.4');
    }
  });

  logger.logStrike({
    strike: {
      ip: '1.2.3.4',
      path: '/.env',
      method: 'GET',
      headers: { host: 'example.com', 'user-agent': 'test-bot' },
      ruleMatched: 'rfc8615_wildcard',
      timestamp: '2026-11-08T18:00:00.000Z'
    },
    actionTaken: 'terminate',
    banStoreName: 'memory',
    banTtlSeconds: 3600
  });

  console.warn = originalWarn;

  assert.strictEqual(callbackCalled, true);
  assert.strictEqual(logged.length, 1);

  const parsed = JSON.parse(logged[0]);
  assert.strictEqual(parsed.event, 'PHINEHAS_SPEAR_STRIKE');
  assert.strictEqual(parsed.verdict.action_taken, 'TCP_SOCKET_TERMINATED');
  assert.strictEqual(parsed.actor.ip, '1.2.3.4');
  assert.strictEqual(parsed.target.path, '/.env');
});
