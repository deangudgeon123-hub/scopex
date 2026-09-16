import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeOperatorTarget, assertOperatorTargetAllowed } from '../lib/scans/operator-target';

test('operator target normalization is exact-domain and blocks local/IP targets', () => {
 assert.equal(normalizeOperatorTarget('https://Example.COM/path?q=1'), 'example.com');
 assert.equal(normalizeOperatorTarget('sub.example.com'), 'sub.example.com');
 assert.throws(() => normalizeOperatorTarget('http://localhost'), /not allowed/i);
 assert.throws(() => normalizeOperatorTarget('https://127.0.0.1'), /not allowed/i);
 assert.throws(() => normalizeOperatorTarget('https://example.com:8443'), /custom ports/i);
});

test('operator allowlist uses exact host matches only', () => {
 const previous = process.env.SCOPEX_OPERATOR_MODE;
 process.env.SCOPEX_OPERATOR_MODE = 'enabled';
 try {
  assert.equal(assertOperatorTargetAllowed('https://example.com', 'example.com,api.example.com'), 'example.com');
  assert.equal(assertOperatorTargetAllowed('api.example.com', 'example.com,api.example.com'), 'api.example.com');
  assert.throws(() => assertOperatorTargetAllowed('evil.example.com', 'example.com,api.example.com'), /allowlist/i);
  assert.throws(() => assertOperatorTargetAllowed('example.com.evil.test', 'example.com'), /allowlist/i);
 } finally {
  if (previous === undefined) delete process.env.SCOPEX_OPERATOR_MODE;
  else process.env.SCOPEX_OPERATOR_MODE = previous;
 }
});
