import test from 'node:test';
import assert from 'node:assert/strict';
import { handleApi } from '../src/routes/api.js';
import worker from '../src/index.js';

const defaultConfig = { name: 'UtilityHub', version: '1.0.0', tagline: 'Minimal' };
const cryptoEnvDisabled = { CRYPTO_ADV_ENABLED: 'false', JWT_HS256_SECRET: 'secret' };
const cryptoEnvEnabled = { CRYPTO_ADV_ENABLED: 'true', JWT_HS256_SECRET: 'secret' };
const networkEnvDisabled = { NETWORK_TOOLS_ENABLED: 'false' };
const networkEnvEnabled = { NETWORK_TOOLS_ENABLED: 'true' };
const perfEnvDisabled = { PERF_TOOLS_ENABLED: 'false' };
const perfEnvEnabled = { PERF_TOOLS_ENABLED: 'true', PERF_ALLOWLIST: 'example.com' };
const highRiskOff = { HIGH_RISK_ENABLED: 'false' };

function makeRequest(url, options = {}) {
  return new Request(url, options);
}

async function readJson(response) {
  const data = await response.json();
  return data;
}

test('/health returns status and requestId', async () => {
  const url = new URL('https://example.com/health');
  const res = await handleApi(makeRequest(url, { method: 'GET' }), {}, {}, { path: '/health', url, config: defaultConfig, requestId: 'req-health' });
  assert.equal(res.status, 200);
  const body = await readJson(res);
  assert.equal(body.requestId, 'req-health');
  assert.equal(body.status, 'ok');
});

test('/api/status returns version and requestId', async () => {
  const url = new URL('https://example.com/api/status');
  const res = await handleApi(makeRequest(url, { method: 'GET' }), {}, {}, { path: '/api/status', url, config: defaultConfig, requestId: 'req-status' });
  const body = await readJson(res);
  assert.equal(res.status, 200);
  assert.equal(body.version, '1.0.0');
  assert.equal(body.requestId, 'req-status');
});

test('invalid inputs use unified error schema', async () => {
  const urlDecodeUrl = new URL('https://example.com/api/url/decode');
  const badUrl = await handleApi(
    makeRequest(urlDecodeUrl, {
      method: 'POST',
      body: JSON.stringify({ encoded: '%E0' }),
      headers: { 'Content-Type': 'application/json' },
    }),
    {},
    {},
    { path: '/api/url/decode', url: urlDecodeUrl, config: defaultConfig, requestId: 'req-bad-url' }
  );
  const badUrlBody = await readJson(badUrl);
  assert.equal(badUrl.status, 400);
  assert.ok(badUrlBody.error);
  assert.equal(badUrlBody.requestId, 'req-bad-url');

  const jsonValidateUrl = new URL('https://example.com/api/json/validate');
  const badJson = await handleApi(
    makeRequest(jsonValidateUrl, {
      method: 'POST',
      body: JSON.stringify({ json: '{bad' }),
      headers: { 'Content-Type': 'application/json' },
    }),
    {},
    {},
    { path: '/api/json/validate', url: jsonValidateUrl, config: defaultConfig, requestId: 'req-bad-json' }
  );
  const badJsonBody = await readJson(badJson);
  assert.equal(badJson.status, 200);
  assert.equal(badJsonBody.valid, false);
  assert.equal(badJsonBody.requestId, 'req-bad-json');

  const jwtUrl = new URL('https://example.com/api/jwt/decode');
  const badJwt = await handleApi(
    makeRequest(jwtUrl, {
      method: 'POST',
      body: JSON.stringify({ jwt: 'abc' }),
      headers: { 'Content-Type': 'application/json' },
    }),
    {},
    {},
    { path: '/api/jwt/decode', url: jwtUrl, config: defaultConfig, requestId: 'req-bad-jwt' }
  );
  const badJwtBody = await readJson(badJwt);
  assert.equal(badJwt.status, 400);
  assert.ok(badJwtBody.error);
  assert.equal(badJwtBody.error.code, 'invalid_jwt');
  assert.equal(badJwtBody.requestId, 'req-bad-jwt');
});

test('post-only endpoint GET returns 405 with Allow header', async () => {
  const url = new URL('https://example.com/api/url/encode');
  const res = await handleApi(
    makeRequest(url, { method: 'GET' }),
    {},
    {},
    { path: '/api/url/encode', url, config: defaultConfig, requestId: 'req-post-only' }
  );
  const body = await readJson(res);
  assert.equal(res.status, 405);
  assert.equal(body.error.code, 'method_not_allowed');
  assert.equal(body.requestId, 'req-post-only');
  assert.equal(res.headers.get('Allow'), 'POST');
});

test('/API path routes to API and returns 405 for post-only', async () => {
  const url = new URL('https://example.com/API/url/encode');
  const res = await worker.fetch(makeRequest(url, { method: 'GET' }), {}, {});
  const body = await readJson(res);
  assert.equal(res.status, 405);
  assert.equal(body.error.code, 'method_not_allowed');
  assert.ok(body.requestId);
  assert.equal(res.headers.get('Allow'), 'POST');
});

test('/api/redirect rejects invalid urls', async () => {
  const url = new URL('https://example.com/api/redirect?url=ftp://bad');
  const res = await handleApi(makeRequest(url, { method: 'GET' }), {}, {}, { path: '/api/redirect', url, config: defaultConfig, requestId: 'req-redirect' });
  const body = await readJson(res);
  assert.equal(res.status, 400);
  assert.equal(body.error.code, 'invalid_url');
  assert.equal(body.requestId, 'req-redirect');
});

test('rate limiting disabled passes through without KV', async () => {
  const url = new URL('https://example.com/api/time');
  const res = await handleApi(makeRequest(url, { method: 'GET' }), { RATE_LIMIT_ENABLED: 'false' }, {}, { path: '/api/time', url, config: defaultConfig, requestId: 'req-rate-off' });
  const body = await readJson(res);
  assert.equal(res.status, 200);
  assert.equal(body.requestId, 'req-rate-off');
});

test('rate limiting enabled returns 429 when over limit', async () => {
  let putCalled = false;
  const kv = {
    async get() {
      return '1';
    },
    async put() {
      putCalled = true;
    },
  };
  const url = new URL('https://example.com/api/time');
  const res = await handleApi(
    makeRequest(url, { method: 'GET' }),
    {
      RATE_LIMIT_ENABLED: 'true',
      RATE_LIMIT_KV: kv,
      RATE_LIMIT_MAX: '1',
      RATE_LIMIT_WINDOW_SEC: '60',
    },
    {},
    { path: '/api/time', url, config: defaultConfig, requestId: 'req-rate-on' }
  );
  const body = await readJson(res);
  assert.equal(res.status, 429);
  assert.equal(body.error.code, 'rate_limited');
  assert.equal(body.requestId, 'req-rate-on');
  assert.ok(res.headers.get('Retry-After'));
  assert.equal(putCalled, false);
});

test('/api/qrcode generates svg', async () => {
  const url = new URL('https://example.com/api/qrcode');
  const res = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ text: 'hello world', ecc: 'M', scale: 6, margin: 2 }),
      headers: { 'Content-Type': 'application/json' },
    }),
    {},
    {},
    { path: '/api/qrcode', url, config: defaultConfig, requestId: 'req-qr' }
  );
  const body = await readJson(res);
  assert.equal(res.status, 200);
  assert.ok(body.svg.startsWith('<svg'));
  assert.equal(body.requestId, 'req-qr');
});

test('/api/qrcode rejects invalid params and oversized text', async () => {
  const url = new URL('https://example.com/api/qrcode');
  const badEcc = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ text: 'hello', ecc: 'Z' }),
      headers: { 'Content-Type': 'application/json' },
    }),
    {},
    {},
    { path: '/api/qrcode', url, config: defaultConfig, requestId: 'req-qr-ecc' }
  );
  const badEccBody = await readJson(badEcc);
  assert.equal(badEcc.status, 400);
  assert.equal(badEccBody.requestId, 'req-qr-ecc');
  assert.equal(badEccBody.error.code, 'invalid_ecc');

  const badScale = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ text: 'hello', scale: 20 }),
      headers: { 'Content-Type': 'application/json' },
    }),
    {},
    {},
    { path: '/api/qrcode', url, config: defaultConfig, requestId: 'req-qr-scale' }
  );
  const badScaleBody = await readJson(badScale);
  assert.equal(badScale.status, 400);
  assert.equal(badScaleBody.requestId, 'req-qr-scale');

  const longText = 'a'.repeat(2000);
  const tooLong = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ text: longText }),
      headers: { 'Content-Type': 'application/json' },
    }),
    {},
    {},
    { path: '/api/qrcode', url, config: defaultConfig, requestId: 'req-qr-long' }
  );
  const tooLongBody = await readJson(tooLong);
  assert.equal(tooLong.status, 400);
  assert.equal(tooLongBody.requestId, 'req-qr-long');
  assert.equal(tooLongBody.error.code, 'invalid_text');
});

test('/api/text/slug generates slug and enforces size', async () => {
  const url = new URL('https://example.com/api/text/slug');
  const res = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ text: 'Hello UtilityHub!' }),
      headers: { 'Content-Type': 'application/json' },
    }),
    {},
    {},
    { path: '/api/text/slug', url, config: defaultConfig, requestId: 'req-slug' }
  );
  const body = await readJson(res);
  assert.equal(res.status, 200);
  assert.equal(body.slug, 'hello-utilityhub');
  assert.equal(body.requestId, 'req-slug');

  const tooLarge = 'a'.repeat(5000);
  const resTooLarge = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ text: tooLarge }),
      headers: { 'Content-Type': 'application/json' },
    }),
    {},
    {},
    { path: '/api/text/slug', url, config: defaultConfig, requestId: 'req-slug-big' }
  );
  const bodyTooLarge = await readJson(resTooLarge);
  assert.equal(resTooLarge.status, 400);
  assert.equal(bodyTooLarge.error.code, 'invalid_text');
  assert.equal(bodyTooLarge.requestId, 'req-slug-big');
});

test('/api/trace returns trace info with requestId', async () => {
  const url = new URL('https://example.com/api/trace');
  const res = await handleApi(
    makeRequest(url, { method: 'GET' }),
    {},
    {},
    { path: '/api/trace', url, config: defaultConfig, requestId: 'req-trace' }
  );
  const body = await readJson(res);
  assert.equal(res.status, 200);
  assert.equal(body.requestId, 'req-trace');
  assert.ok('colo' in body);
});

test('advanced crypto disabled returns feature_disabled', async () => {
  const url = new URL('https://example.com/api/password/hash');
  const res = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ password: 'secret', salt: 's' }),
      headers: { 'Content-Type': 'application/json' },
    }),
    cryptoEnvDisabled,
    {},
    { path: '/api/password/hash', url, config: defaultConfig, requestId: 'req-adv-off' }
  );
  const body = await readJson(res);
  assert.equal(res.status, 403);
  assert.equal(body.error.code, 'feature_disabled');
  assert.equal(body.requestId, 'req-adv-off');
});

test('pbkdf2 hashing works when enabled and enforces limits', async () => {
  const url = new URL('https://example.com/api/password/hash');
  const res = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ password: 'secret', salt: 'salt', iterations: 120000, length: 32, hash: 'SHA-256' }),
      headers: { 'Content-Type': 'application/json' },
    }),
    cryptoEnvEnabled,
    {},
    { path: '/api/password/hash', url, config: defaultConfig, requestId: 'req-pbkdf2' }
  );
  const body = await readJson(res);
  assert.equal(res.status, 200);
  assert.equal(body.algorithm, 'PBKDF2-SHA256');
  assert.equal(body.length, 32);
  assert.ok(body.derivedKey);

  const longPassword = 'a'.repeat(5000);
  const tooLong = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ password: longPassword, salt: 's' }),
      headers: { 'Content-Type': 'application/json' },
    }),
    cryptoEnvEnabled,
    {},
    { path: '/api/password/hash', url, config: defaultConfig, requestId: 'req-pbkdf2-long' }
  );
  const tooLongBody = await readJson(tooLong);
  assert.equal(tooLong.status, 400);
  assert.equal(tooLongBody.error.code, 'invalid_password');
});

test('jwt sign and verify when enabled', async () => {
  const signUrl = new URL('https://example.com/api/jwt/sign');
  const signRes = await handleApi(
    makeRequest(signUrl, {
      method: 'POST',
      body: JSON.stringify({ payload: { sub: '123' }, ttlSeconds: 3600 }),
      headers: { 'Content-Type': 'application/json' },
    }),
    cryptoEnvEnabled,
    {},
    { path: '/api/jwt/sign', url: signUrl, config: defaultConfig, requestId: 'req-jwt-sign' }
  );
  const signBody = await readJson(signRes);
  assert.equal(signRes.status, 200);
  assert.ok(signBody.jwt);

  const verifyUrl = new URL('https://example.com/api/jwt/verify');
  const verifyRes = await handleApi(
    makeRequest(verifyUrl, {
      method: 'POST',
      body: JSON.stringify({ jwt: signBody.jwt }),
      headers: { 'Content-Type': 'application/json' },
    }),
    cryptoEnvEnabled,
    {},
    { path: '/api/jwt/verify', url: verifyUrl, config: defaultConfig, requestId: 'req-jwt-verify' }
  );
  const verifyBody = await readJson(verifyRes);
  assert.equal(verifyRes.status, 200);
  assert.equal(verifyBody.valid, true);
});

test('jwt verify detects tampering', async () => {
  const verifyUrl = new URL('https://example.com/api/jwt/verify');
  const tampered = 'a.b.c';
  const verifyRes = await handleApi(
    makeRequest(verifyUrl, {
      method: 'POST',
      body: JSON.stringify({ jwt: tampered }),
      headers: { 'Content-Type': 'application/json' },
    }),
    cryptoEnvEnabled,
    {},
    { path: '/api/jwt/verify', url: verifyUrl, config: defaultConfig, requestId: 'req-jwt-bad' }
  );
  const verifyBody = await readJson(verifyRes);
  assert.equal(verifyRes.status, 200);
  assert.equal(verifyBody.valid, false);
  assert.equal(verifyBody.requestId, 'req-jwt-bad');
});

test('network tools disabled returns feature_disabled', async () => {
  const url = new URL('https://example.com/api/dns/resolve');
  const res = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ name: 'example.com', type: 'A' }),
      headers: { 'Content-Type': 'application/json' },
    }),
    networkEnvDisabled,
    {},
    { path: '/api/dns/resolve', url, config: defaultConfig, requestId: 'req-dns-off' }
  );
  const body = await readJson(res);
  assert.equal(res.status, 403);
  assert.equal(body.error.code, 'feature_disabled');
  assert.equal(body.requestId, 'req-dns-off');
});

test('/api/compress/test enforces size and not_supported when missing CompressionStream', async () => {
  const url = new URL('https://example.com/api/compress/test');
  const tooLong = 'a'.repeat(70000);
  const resLong = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ text: tooLong }),
      headers: { 'Content-Type': 'application/json' },
    }),
    networkEnvEnabled,
    {},
    { path: '/api/compress/test', url, config: defaultConfig, requestId: 'req-compress-long' }
  );
  const bodyLong = await readJson(resLong);
  assert.equal(resLong.status, 400);
  assert.equal(bodyLong.error.code, 'invalid_text');

  const resSupport = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ text: 'hello' }),
      headers: { 'Content-Type': 'application/json' },
    }),
    networkEnvEnabled,
    {},
    { path: '/api/compress/test', url, config: defaultConfig, requestId: 'req-compress-support' }
  );
  const bodySupport = await readJson(resSupport);
  assert.equal(bodySupport.requestId, 'req-compress-support');
  // In Node, CompressionStream may be unavailable; accept not_supported.
  if (resSupport.status === 501) {
    assert.equal(bodySupport.error.code, 'not_supported');
  } else {
    assert.equal(resSupport.status, 200);
    assert.ok(bodySupport.gzipBytes);
  }
});

test('/api/dns/resolve validates hostname, type, and allowlist', async () => {
  const url = new URL('https://example.com/api/dns/resolve');
  const badName = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ name: '1.1.1.1', type: 'A' }),
      headers: { 'Content-Type': 'application/json' },
    }),
    networkEnvEnabled,
    {},
    { path: '/api/dns/resolve', url, config: defaultConfig, requestId: 'req-dns-bad' }
  );
  const badNameBody = await readJson(badName);
  assert.equal(badName.status, 400);
  assert.equal(badNameBody.error.code, 'invalid_name');

  const disallowed = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ name: 'notallowed.com', type: 'A' }),
      headers: { 'Content-Type': 'application/json' },
    }),
    { ...networkEnvEnabled, DNS_ALLOWLIST: 'example.com' },
    {},
    { path: '/api/dns/resolve', url, config: defaultConfig, requestId: 'req-dns-allow' }
  );
  const disallowedBody = await readJson(disallowed);
  assert.equal(disallowed.status, 400);
  assert.equal(disallowedBody.error.code, 'invalid_name');
});

test('perf tools disabled returns feature_disabled', async () => {
  const url = new URL('https://example.com/api/perf/benchmark');
  const res = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ url: 'https://example.com' }),
      headers: { 'Content-Type': 'application/json' },
    }),
    perfEnvDisabled,
    {},
    { path: '/api/perf/benchmark', url, config: defaultConfig, requestId: 'req-perf-off' }
  );
  const body = await readJson(res);
  assert.equal(res.status, 403);
  assert.equal(body.error.code, 'feature_disabled');
  assert.equal(body.requestId, 'req-perf-off');
});

test('/api/perf/benchmark rejects non-allowlist and private hosts', async () => {
  const url = new URL('https://example.com/api/perf/benchmark');
  const disallowed = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ url: 'https://notallowed.com' }),
      headers: { 'Content-Type': 'application/json' },
    }),
    perfEnvEnabled,
    {},
    { path: '/api/perf/benchmark', url, config: defaultConfig, requestId: 'req-perf-allow' }
  );
  const bodyDisallowed = await readJson(disallowed);
  assert.equal(disallowed.status, 400);
  assert.equal(bodyDisallowed.error.code, 'invalid_url');

  const privateHost = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ url: 'http://127.0.0.1' }),
      headers: { 'Content-Type': 'application/json' },
    }),
    perfEnvEnabled,
    {},
    { path: '/api/perf/benchmark', url, config: defaultConfig, requestId: 'req-perf-private' }
  );
  const bodyPrivate = await readJson(privateHost);
  assert.equal(privateHost.status, 400);
  assert.equal(bodyPrivate.error.code, 'invalid_url');
});

test('/api/ip/geolocate gating and anonymization', async () => {
  const url = new URL('https://example.com/api/ip/geolocate');
  const disabled = await handleApi(
    makeRequest(url, { method: 'POST', headers: { 'Content-Type': 'application/json' } }),
    { GEOLOOKUP_ENABLED: 'false' },
    {},
    { path: '/api/ip/geolocate', url, config: defaultConfig, requestId: 'req-geo-off' }
  );
  const disabledBody = await readJson(disabled);
  assert.equal(disabled.status, 403);
  assert.equal(disabledBody.error.code, 'feature_disabled');

  const enabled = await handleApi(
    makeRequest(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'cf-connecting-ip': '1.2.3.4' } }),
    { GEOLOOKUP_ENABLED: 'true' },
    {},
    { path: '/api/ip/geolocate', url, config: defaultConfig, requestId: 'req-geo-on' }
  );
  const enabledBody = await readJson(enabled);
  assert.equal(enabled.status, 200);
  assert.equal(enabledBody.ip, '1.2.3.0');
  assert.equal(enabledBody.requestId, 'req-geo-on');
});

test('high-risk master gate enforced', async () => {
  const url = new URL('https://example.com/api/proxy');
  const res = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ url: 'https://example.com' }),
      headers: { 'Content-Type': 'application/json' },
    }),
    highRiskOff,
    {},
    { path: '/api/proxy', url, config: defaultConfig, requestId: 'req-hr-off' }
  );
  const body = await readJson(res);
  assert.equal(res.status, 403);
  assert.equal(body.error.code, 'feature_disabled');
});

test('/api/proxy rejects disallowed hosts', async () => {
  const url = new URL('https://example.com/api/proxy');
  const res = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ url: 'http://127.0.0.1' }),
      headers: { 'Content-Type': 'application/json' },
    }),
    { HIGH_RISK_ENABLED: 'true', PROXY_ENABLED: 'true', PROXY_ALLOWLIST: 'example.com' },
    {},
    { path: '/api/proxy', url, config: defaultConfig, requestId: 'req-proxy-host' }
  );
  const body = await readJson(res);
  assert.equal(res.status, 400);
  assert.equal(body.error.code, 'invalid_url');
});

test('/api/schema/validate catches errors', async () => {
  const url = new URL('https://example.com/api/schema/validate');
  const res = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({
        schema: { type: 'object', properties: { id: { type: 'number' } }, required: ['id'] },
        data: { id: 'oops' },
      }),
      headers: { 'Content-Type': 'application/json' },
    }),
    { HIGH_RISK_ENABLED: 'true', SCHEMA_VALIDATE_ENABLED: 'true' },
    {},
    { path: '/api/schema/validate', url, config: defaultConfig, requestId: 'req-schema' }
  );
  const body = await readJson(res);
  assert.equal(res.status, 200);
  assert.equal(body.valid, false);
  assert.ok(body.errors.length > 0);
});

test('/api/mock respects depth/item gating', async () => {
  const url = new URL('https://example.com/api/mock');
  const res = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ schema: { type: 'object', properties: { id: { type: 'number' } } } }),
      headers: { 'Content-Type': 'application/json' },
    }),
    { HIGH_RISK_ENABLED: 'true', MOCK_ENABLED: 'true' },
    {},
    { path: '/api/mock', url, config: defaultConfig, requestId: 'req-mock' }
  );
  const body = await readJson(res);
  assert.equal(res.status, 200);
  assert.ok(body.data);
});

test('/api/vuln/scan enforces max length and returns findings array', async () => {
  const url = new URL('https://example.com/api/vuln/scan');
  const resFindings = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ text: '<script>alert(1)</script>' }),
      headers: { 'Content-Type': 'application/json' },
    }),
    { HIGH_RISK_ENABLED: 'true', VULN_SCAN_ENABLED: 'true' },
    {},
    { path: '/api/vuln/scan', url, config: defaultConfig, requestId: 'req-vuln' }
  );
  const bodyFindings = await readJson(resFindings);
  assert.equal(resFindings.status, 200);
  assert.ok(Array.isArray(bodyFindings.findings));

  const longText = 'a'.repeat(90000);
  const resLong = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ text: longText }),
      headers: { 'Content-Type': 'application/json' },
    }),
    { HIGH_RISK_ENABLED: 'true', VULN_SCAN_ENABLED: 'true', VULN_MAX_TEXT: '8192' },
    {},
    { path: '/api/vuln/scan', url, config: defaultConfig, requestId: 'req-vuln-long' }
  );
  const bodyLong = await readJson(resLong);
  assert.equal(resLong.status, 400);
  assert.equal(bodyLong.error.code, 'invalid_text');
});

test('/api/playground allows only permitted modes', async () => {
  const url = new URL('https://example.com/api/playground');
  const resBad = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ mode: 'exec', payload: {} }),
      headers: { 'Content-Type': 'application/json' },
    }),
    { HIGH_RISK_ENABLED: 'true', PLAYGROUND_ENABLED: 'true' },
    {},
    { path: '/api/playground', url, config: defaultConfig, requestId: 'req-play-bad' }
  );
  assert.equal(resBad.status, 400);

  const resEcho = await handleApi(
    makeRequest(url, {
      method: 'POST',
      body: JSON.stringify({ mode: 'echo', payload: { msg: 'hi' } }),
      headers: { 'Content-Type': 'application/json' },
    }),
    { HIGH_RISK_ENABLED: 'true', PLAYGROUND_ENABLED: 'true' },
    {},
    { path: '/api/playground', url, config: defaultConfig, requestId: 'req-play-echo' }
  );
  const bodyEcho = await readJson(resEcho);
  assert.equal(resEcho.status, 200);
  assert.equal(bodyEcho.mode, 'echo');
});
