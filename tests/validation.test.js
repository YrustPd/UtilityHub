import test from 'node:test';
import assert from 'node:assert/strict';
import { parseAllowlist, guardUrlLength } from '../src/helpers/validation.js';

test('allowlist parses and lowercases entries', () => {
  const result = parseAllowlist('Foo.com, Bar.com ,');
  assert.deepEqual(result, ['foo.com', 'bar.com']);
});

test('allowlist normalizes schemes, wildcards, ports, and trailing dots', () => {
  const result = parseAllowlist('https://Example.com:443/path,*.Foo.com,.Bar.com,localhost:8080,[::1],Example.net.');
  assert.deepEqual(result, ['example.com', 'foo.com', 'bar.com', 'localhost', '::1', 'example.net']);
});

test('guardUrlLength enforces maximum length', () => {
  const ok = guardUrlLength('https://example.com', 2048);
  assert.equal(ok.ok, true);
  const tooLong = guardUrlLength('x'.repeat(3000), 1024);
  assert.equal(tooLong.ok, false);
});
