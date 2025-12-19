import test from 'node:test';
import assert from 'node:assert/strict';
import {
  base64UrlEncode,
  base64UrlDecode,
  hexEncode,
  hexDecode,
  utf8ToBytes,
} from '../src/helpers/utils.js';
import { guardSize, parseAllowlist, guardUrlLength } from '../src/helpers/validation.js';

test('base64url roundtrip', () => {
  const text = 'hello-~utility';
  const encoded = base64UrlEncode(utf8ToBytes(text));
  const decoded = base64UrlDecode(encoded);
  assert.equal(decoded, text);
});

test('hex encode/decode valid', () => {
  const hex = hexEncode('hi');
  assert.equal(hex, '6869');
  const decoded = hexDecode(hex);
  assert.equal(decoded, 'hi');
});

test('hex decode rejects odd length or invalid chars', () => {
  assert.equal(hexDecode('abc'), null);
  assert.equal(hexDecode('zz'), null);
});

test('guardSize enforces limits', () => {
  const ok = guardSize(10, 32);
  assert.equal(ok.ok, true);
  const tooLarge = guardSize(40, 32);
  assert.equal(tooLarge.ok, false);
});

test('allowlist parsing and url length guard', () => {
  const list = parseAllowlist('Example.com, test.com ,');
  assert.deepEqual(list, ['example.com', 'test.com']);
  const shortUrl = guardUrlLength('https://example.com', 10_000);
  assert.equal(shortUrl.ok, true);
  const longUrl = guardUrlLength('x'.repeat(5000), 1024);
  assert.equal(longUrl.ok, false);
});
