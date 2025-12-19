import test from 'node:test';
import assert from 'node:assert/strict';
import { handleApi } from '../src/routes/api.js';

const config = { name: 'UtilityHub', version: '1.0.0', tagline: 'Minimal' };

function makeRequest(url, options = {}) {
  return new Request(url, options);
}

async function readJson(response) {
  return response.json();
}

test('success responses include requestId', async () => {
  const url = new URL('https://example.com/health');
  const res = await handleApi(makeRequest(url, { method: 'GET' }), {}, {}, { path: '/health', url, config, requestId: 'snap-1' });
  const body = await readJson(res);
  assert.equal(res.status, 200);
  assert.equal(body.requestId, 'snap-1');
});

test('error responses are unified and include requestId', async () => {
  const url = new URL('https://example.com/api/url/decode');
  const res = await handleApi(
    makeRequest(url, { method: 'POST', body: '{"encoded":"%E0"}', headers: { 'Content-Type': 'application/json' } }),
    {},
    {},
    { path: '/api/url/decode', url, config, requestId: 'snap-err' }
  );
  const body = await readJson(res);
  assert.equal(res.status, 400);
  assert.ok(body.error);
  assert.equal(body.requestId, 'snap-err');
});
