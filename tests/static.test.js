import test from 'node:test';
import assert from 'node:assert/strict';
import { handleStatic } from '../src/routes/static.js';
import worker from '../src/index.js';

function makeRequest(url, options = {}) {
  return new Request(url, options);
}

test('sitemap is prefix-aware', async () => {
  const url = new URL('https://example.com/hub/sitemap.xml');
  const res = await handleStatic(makeRequest(url), {}, {}, {
    path: '/sitemap.xml',
    url,
    config: { prefix: '/hub' },
  });
  const text = await res.text();
  assert.equal(res.status, 200);
  assert.ok(text.includes('https://example.com/hub/'));
  assert.ok(text.includes('https://example.com/hub/api/status'));
});

test('ui returns html with security headers and version', async () => {
  const url = new URL('https://example.com/');
  const res = await worker.fetch(makeRequest(url, { method: 'GET' }), {}, {});
  const text = await res.text();
  assert.equal(res.status, 200);
  assert.ok(res.headers.get('Content-Type')?.includes('text/html'));
  assert.ok(res.headers.get('Content-Security-Policy'));
  assert.equal(res.headers.get('X-Content-Type-Options'), 'nosniff');
  assert.equal(res.headers.get('Referrer-Policy'), 'no-referrer');
  assert.ok(text.includes('v1.0.0'));
});
