import {
  jsonResponse,
  nowIso,
  randomId,
  base64Encode,
  base64Decode,
  hexEncode,
  hexDecode,
  base64UrlDecode,
  base64UrlEncode,
  utf8ToBytes,
  generateQrSvg,
  bytesToBase64,
  anonymizeIp,
  base64ToBytes,
} from '../helpers/utils.js';
import {
  isNonEmptyString,
  requiredString,
  guardSize,
  parseAllowlist,
  guardUrlLength,
  isHostname,
  isIpLiteral,
  matchesAllowlist,
  isPrivateIp,
} from '../helpers/validation.js';

const cacheControlNoStore = { 'Cache-Control': 'no-store' };
const UINT32_MAX = 0xffffffff;
const MAX_REGEX_PATTERN = 1024;
const MAX_REGEX_TEXT = 8 * 1024;
const MAX_QUERY_LENGTH = 16 * 1024;
const MAX_PASSWORD_LENGTH = 128;
const MAX_SLUG_TEXT = 4096;
const MAX_PASSWORD_INPUT = 4096;
const MAX_JWT_LENGTH = 4096;
const MAX_COMPRESS_TEXT = 64 * 1024;
const MAX_PROXY_BYTES_DEFAULT = 262144;
const MAX_PROXY_BYTES_CAP = 1048576;
const MAX_VULN_TEXT_DEFAULT = 8192;
const MAX_VULN_TEXT_CAP = 32768;

function errorResponse(code, message, status = 400, requestId, hints) {
  const payload = { error: { code, message }, requestId };
  if (hints) payload.hints = hints;
  return jsonResponse(payload, status, cacheControlNoStore);
}

function errorResponseWithHeaders(code, message, status = 400, requestId, hints, extraHeaders = {}) {
  const payload = { error: { code, message }, requestId };
  if (hints) payload.hints = hints;
  return jsonResponse(payload, status, { ...cacheControlNoStore, ...extraHeaders });
}

function joinPrefix(config, path) {
  const base = config?.prefix && config.prefix !== '/' ? config.prefix : '';
  const clean = path.startsWith('/') ? path : `/${path}`;
  return `${base}${clean}`;
}

function hintBodyFor(path) {
  switch (path) {
    case '/api/base64/encode':
      return { text: 'hello' };
    case '/api/base64/decode':
      return { base64: 'aGVsbG8=' };
    case '/api/url/encode':
      return { text: 'hello world' };
    case '/api/url/decode':
      return { encoded: 'hello%20world' };
    case '/api/hex/encode':
      return { text: 'hello' };
    case '/api/hex/decode':
      return { hex: '68656c6c6f' };
    case '/api/json/format':
    case '/api/json/minify':
    case '/api/json/validate':
      return { json: '{"hello":"world"}' };
    case '/api/hmac':
      return { text: 'hello', key: 'secret' };
    case '/api/jwt/decode':
      return { jwt: 'header.payload.signature' };
    case '/api/crypto/keypair':
    case '/api/crypto/publickey':
      return {};
    case '/api/validate/url':
      return { url: 'https://example.com' };
    case '/api/validate/ip':
      return { ip: '127.0.0.1' };
    case '/api/text/slug':
      return { text: 'Hello world' };
    case '/api/password/hash':
      return { password: 'secret', salt: 'salt', iterations: 120000, length: 32, hash: 'SHA-256' };
    case '/api/dns/resolve':
      return { name: 'example.com', type: 'A' };
    case '/api/compress/test':
      return { text: 'example payload' };
    case '/api/perf/benchmark':
      return { url: 'https://example.com', method: 'GET' };
    case '/api/ip/geolocate':
      return { ip: '1.1.1.1' };
    case '/api/proxy':
      return { url: 'https://example.com', method: 'GET' };
    case '/api/schema/validate':
      return { schema: { type: 'object' }, data: {} };
    case '/api/mock':
      return { schema: { type: 'object' } };
    case '/api/vuln/scan':
      return { text: 'select * from users' };
    case '/api/playground':
      return { mode: 'echo', payload: 'hello' };
    case '/api/jwt/sign':
      return { payload: { sub: '123' } };
    case '/api/jwt/verify':
      return { jwt: 'header.payload.signature' };
    default:
      return {};
  }
}

function methodNotAllowedWithHints(path, requestId, url, config) {
  const fullPath = joinPrefix(config, path);
  const body = hintBodyFor(path);
  const json = JSON.stringify(body);
  const escapedJson = json.replace(/'/g, "'\"'\"'");
  const curl = `curl -X POST ${url.origin}${fullPath} -H 'Content-Type: application/json' -d '${escapedJson}'`;
  const fetchSnippet = `await fetch('${fullPath}', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(${json}) });`;
  return errorResponseWithHeaders(
    'method_not_allowed',
    'Only POST is supported',
    405,
    requestId,
    { curl, fetch: fetchSnippet },
    { Allow: 'POST' }
  );
}

function postOnlyGuard(method, path, requestId, url, config) {
  if (method === 'POST') return null;
  if (method === 'GET') return methodNotAllowedWithHints(path, requestId, url, config);
  return errorResponseWithHeaders('method_not_allowed', 'Only POST is supported', 405, requestId, null, { Allow: 'POST' });
}

async function readJsonBody(request, limit = 32 * 1024) {
  const lengthHeader = request.headers.get('content-length');
  if (lengthHeader) {
    const parsedLength = Number(lengthHeader);
    const sizeCheck = guardSize(parsedLength, limit);
    if (!sizeCheck.ok) return { error: sizeCheck.message };
  }

  let text = '';
  try {
    text = await request.text();
  } catch (error) {
    return { error: 'Unable to read request body' };
  }

  const sizeCheck = guardSize(new TextEncoder().encode(text).byteLength, limit);
  if (!sizeCheck.ok) return { error: sizeCheck.message };

  try {
    const parsed = text ? JSON.parse(text) : {};
    return { value: parsed, raw: text };
  } catch (error) {
    return { error: 'Body must be valid JSON' };
  }
}

function pickIp(request) {
  const direct = request.headers.get('cf-connecting-ip');
  if (isNonEmptyString(direct)) return direct;
  const forwarded = request.headers.get('x-forwarded-for');
  if (isNonEmptyString(forwarded)) return forwarded.split(',')[0].trim();
  return 'unknown';
}

function safeHeaders(request) {
  const allowed = ['accept', 'accept-language', 'user-agent'];
  const headers = {};
  allowed.forEach((key) => {
    const value = request.headers.get(key);
    if (value) headers[key] = value;
  });
  return headers;
}

function parseInteger(value) {
  if (value === null || value === undefined || value === '') return null;
  const num = Number(value);
  if (!Number.isFinite(num) || !Number.isInteger(num)) return null;
  return num;
}

function base64UrlToBytes(str) {
  const normalized = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  return base64ToBytes(normalized + padding);
}

function randomInt(min, max) {
  const range = max - min + 1;
  if (range <= 0) throw new Error('Invalid range');
  const maxAcceptable = Math.floor(UINT32_MAX / range) * range;
  const buf = new Uint32Array(1);
  let candidate;
  do {
    crypto.getRandomValues(buf);
    candidate = buf[0];
  } while (candidate >= maxAcceptable);
  return min + (candidate % range);
}

async function sha256Hex(value) {
  const encoder = new TextEncoder();
  const data = encoder.encode(value);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(hashBuffer);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function parseUserAgent(ua) {
  const raw = ua || '';
  const lower = raw.toLowerCase();
  const browser =
    /firefox/i.test(raw) ? 'Firefox' : /chrome|crios/i.test(raw) ? 'Chrome' : /safari/i.test(raw) ? 'Safari' : 'Unknown';
  const os =
    /windows/i.test(raw)
      ? 'Windows'
      : /mac os x|macintosh/i.test(raw)
      ? 'macOS'
      : /android/i.test(raw)
      ? 'Android'
      : /linux/i.test(raw)
      ? 'Linux'
      : /iphone|ipad|ipod/i.test(raw)
      ? 'iOS'
      : 'Unknown';
  return { raw, browser, os, mobile: /mobile/i.test(lower) };
}

function shortId() {
  const length = 8 + randomInt(0, 4);
  return randomId(length);
}

function statusFeatures() {
  return [
    'diagnostics: health, status, ping',
    'identity: whoami, ip, headers, useragent',
    'time: time',
    'random: integer',
    'crypto: hash',
    'identifiers: uuid, shortid',
    'redirect: 302',
    'encoding: base64, url, hex',
    'json: format, minify, validate',
    'crypto-adv: hmac, jwt decode, ecdsa',
    'validation: url, ip',
    'text: regex, lorem, password',
    'qr: qrcode',
  ];
}

function boolFromEnv(value) {
  return String(value || '').toLowerCase() === 'true';
}

function selectBackend(env) {
  const pref = (env?.RATE_LIMIT_BACKEND || 'auto').toLowerCase();
  const hasDO = Boolean(env?.RATE_LIMIT_DO);
  const hasKV = Boolean(env?.RATE_LIMIT_KV);
  if (pref === 'do') return hasDO ? 'do' : hasKV ? 'kv' : 'none';
  if (pref === 'kv') return hasKV ? 'kv' : 'none';
  if (pref === 'auto') return hasDO ? 'do' : hasKV ? 'kv' : 'none';
  return 'none';
}

function rateGroup(path) {
  if (
    path.startsWith('/api/hash') ||
    path.startsWith('/api/hmac') ||
    path.startsWith('/api/jwt') ||
    path.startsWith('/api/crypto/') ||
    path.startsWith('/api/password') ||
    path.startsWith('/api/qrcode') ||
    path.startsWith('/api/dns/resolve') ||
    path.startsWith('/api/compress/test') ||
    path.startsWith('/api/perf/benchmark') ||
    path.startsWith('/api/ip/geolocate') ||
    path.startsWith('/api/proxy') ||
    path.startsWith('/api/mock') ||
    path.startsWith('/api/schema/validate') ||
    path.startsWith('/api/vuln/scan') ||
    path.startsWith('/api/playground')
  ) {
    return 'crypto';
  }
  return 'default';
}

async function checkRateLimit(request, env, path, requestId, loggingEnabled) {
  const enabled = boolFromEnv(env?.RATE_LIMIT_ENABLED);
  const backend = selectBackend(env);
  const kv = env?.RATE_LIMIT_KV;
  const rateLimiterDO = env?.RATE_LIMIT_DO;
  if (!enabled) return { allowed: true, backend: 'none' };
  if (backend === 'none') {
    if (loggingEnabled) console.warn(`[rate-limit] ${requestId} enabled without a configured backend`);
    return { allowed: false, backend: 'none', reason: 'unconfigured' };
  }

  const windowSec = Number(env.RATE_LIMIT_WINDOW_SEC) || 60;
  const maxDefault = Number(env.RATE_LIMIT_MAX) || 60;
  const maxCrypto = Number(env.RATE_LIMIT_MAX_CRYPTO) || 20;

  const group = rateGroup(path);
  const limit = group === 'crypto' ? maxCrypto : maxDefault;

  const ip = pickIp(request) || 'unknown';
  const key = `${group}:${ip}`;

  if (backend === 'do' && rateLimiterDO) {
    try {
      const id = rateLimiterDO.idFromName(key);
      const stub = rateLimiterDO.get(id);
      const resp = await stub.fetch('https://rate-limit', {
        method: 'POST',
        body: JSON.stringify({ key, windowSec, limit }),
      });
      if (!resp.ok) return { allowed: true, backend: 'do' };
      const data = await resp.json();
      const nowSec = Math.floor(Date.now() / 1000);
      const retryAfter = Math.max(1, (data.resetEpoch || nowSec) - nowSec);
      return {
        allowed: Boolean(data.allowed),
        retryAfter,
        limit,
        remaining: data.remaining,
        resetEpoch: data.resetEpoch,
        backend: 'do',
      };
    } catch (error) {
      if (loggingEnabled) console.warn(`[rate-limit] ${requestId} ${error.message}`);
      return { allowed: true, backend: 'do' };
    }
  }

  if (backend === 'kv' && kv) {
    const nowSec = Math.floor(Date.now() / 1000);
    const windowKey = Math.floor(nowSec / windowSec);
    const retryAfter = windowSec - (nowSec % windowSec || 0) || windowSec;
    try {
      const parsed = JSON.parse((await kv.get(key)) || 'null') || { bucket: null, count: 0 };
      const stored = typeof parsed === 'number' ? { bucket: windowKey, count: parsed } : parsed;
      const count =
        stored.bucket === windowKey ? stored.count : typeof stored.count === 'number' ? stored.count : 0;
      const allowed = count < limit;
      const nextCount = allowed ? count + 1 : count;
      if (allowed) {
        await kv.put(key, JSON.stringify({ bucket: windowKey, count: nextCount }), { expirationTtl: windowSec * 2 });
      }
      const remaining = Math.max(0, limit - nextCount);
      return {
        allowed,
        retryAfter,
        limit,
        remaining,
        resetEpoch: (windowKey + 1) * windowSec,
        backend: 'kv',
      };
    } catch (error) {
      if (loggingEnabled) console.warn(`[rate-limit] ${requestId} ${error.message}`);
      return { allowed: true, backend: 'kv' };
    }
  }

  return { allowed: true, backend: 'none' };
}

export async function handleApi(request, env, ctx, meta = {}) {
  const { path, config = {}, hostname, url, requestId, loggingEnabled } = meta;

  const method = request.method.toUpperCase();
  const respond = (payload, status = 200) =>
    jsonResponse({ ...payload, requestId }, status, cacheControlNoStore);

  if (url?.search?.length > MAX_QUERY_LENGTH) {
    return errorResponse('invalid_query', 'query string too long', 414, requestId);
  }

  if (path === '/health') {
    if (method !== 'GET') return errorResponse('method_not_allowed', 'Only GET is supported', 405, requestId);
    return respond({ status: 'ok', service: config.name || 'UtilityHub', hostname, time: nowIso() });
  }

  if (path.startsWith('/api/')) {
    const rateResult = await checkRateLimit(request, env, path, requestId, loggingEnabled);
    if (!rateResult.allowed) {
      if (rateResult.reason === 'unconfigured') {
        return errorResponse('invalid_config', 'Rate limiting enabled but no backend configured', 500, requestId);
      }
      const headers = { ...cacheControlNoStore, 'Retry-After': String(rateResult.retryAfter) };
      return jsonResponse(
        {
          error: { code: 'rate_limited', message: 'Rate limit exceeded' },
          retryAfterSeconds: rateResult.retryAfter,
          limit: rateResult.limit,
          remaining: rateResult.remaining,
          resetEpoch: rateResult.resetEpoch,
          requestId,
        },
        429,
        headers
      );
    }
  }

  if (path === '/api/status') {
    if (method !== 'GET') return errorResponse('method_not_allowed', 'Only GET is supported', 405, requestId);
    const backendSelected = selectBackend(env);
    const rateEnabled = boolFromEnv(env?.RATE_LIMIT_ENABLED) && backendSelected !== 'none';
    const cryptoAdvEnabled = boolFromEnv(env?.CRYPTO_ADV_ENABLED);
    const networkToolsEnabled = boolFromEnv(env?.NETWORK_TOOLS_ENABLED);
    const perfToolsEnabled = boolFromEnv(env?.PERF_TOOLS_ENABLED);
    const geolookupEnabled = boolFromEnv(env?.GEOLOOKUP_ENABLED);
    const highRiskEnabled = boolFromEnv(env?.HIGH_RISK_ENABLED);
    return respond({
      name: config.name || 'UtilityHub',
      version: config.version || '1.0.0',
      time: nowIso(),
      features: statusFeatures(),
      rateLimit: {
        enabled: rateEnabled,
        backend: backendSelected === 'do' ? 'durable_object' : backendSelected === 'kv' ? 'kv' : 'none',
        windowSec: Number(env.RATE_LIMIT_WINDOW_SEC) || 60,
        maxDefault: Number(env.RATE_LIMIT_MAX) || 60,
        maxCrypto: Number(env.RATE_LIMIT_MAX_CRYPTO) || 20,
      },
      logging: { enabled: boolFromEnv(env?.LOGGING_ENABLED) },
      cryptoAdvancedEnabled: cryptoAdvEnabled,
      networkToolsEnabled,
      perfToolsEnabled,
      geolookupEnabled,
      highRiskEnabled,
      proxyEnabled: highRiskEnabled && boolFromEnv(env?.PROXY_ENABLED),
      mockEnabled: highRiskEnabled && boolFromEnv(env?.MOCK_ENABLED),
      schemaValidateEnabled: highRiskEnabled && boolFromEnv(env?.SCHEMA_VALIDATE_ENABLED),
      vulnScanEnabled: highRiskEnabled && boolFromEnv(env?.VULN_SCAN_ENABLED),
      playgroundEnabled: highRiskEnabled && boolFromEnv(env?.PLAYGROUND_ENABLED),
    });
  }

  if (path === '/api/ping') {
    if (method !== 'GET') return errorResponse('method_not_allowed', 'Only GET is supported', 405, requestId);
    const received = nowIso();
    const responded = nowIso();
    return respond({ received, responded });
  }

  if (path === '/api/whoami') {
    if (method !== 'GET') return errorResponse('method_not_allowed', 'Only GET is supported', 405, requestId);
    const cf = request.cf || {};
    return respond({
      ip: pickIp(request),
      user_agent: request.headers.get('user-agent') || '',
      cf: {
        colo: cf.colo || null,
        country: cf.country || null,
        timezone: cf.timezone || null,
        asn: cf.asn || null,
      },
    });
  }

  if (path === '/api/trace') {
    if (method !== 'GET') return errorResponse('method_not_allowed', 'Only GET is supported', 405, requestId);
    const cf = request.cf || {};
    return respond({
      colo: cf.colo || null,
      country: cf.country || null,
      asn: cf.asn || null,
    });
  }

  if (path === '/api/ip') {
    if (method !== 'GET') return errorResponse('method_not_allowed', 'Only GET is supported', 405, requestId);
    return respond({ ip: pickIp(request) });
  }

  if (path === '/api/headers') {
    if (method !== 'GET') return errorResponse('method_not_allowed', 'Only GET is supported', 405, requestId);
    return respond({ headers: safeHeaders(request) });
  }

  if (path === '/api/useragent') {
    if (method !== 'GET') return errorResponse('method_not_allowed', 'Only GET is supported', 405, requestId);
    return respond({ user_agent: parseUserAgent(request.headers.get('user-agent')) });
  }

  if (path === '/api/time') {
    if (method !== 'GET') return errorResponse('method_not_allowed', 'Only GET is supported', 405, requestId);
    return respond({ iso: nowIso() });
  }

  if (path === '/api/random') {
    if (method !== 'GET') return errorResponse('method_not_allowed', 'Only GET is supported', 405, requestId);
    const params = url.searchParams;
    const rawMin = params.get('min');
    const rawMax = params.get('max');
    const minParam = parseInteger(rawMin);
    const maxParam = parseInteger(rawMax);

    if (rawMin !== null && minParam === null) {
      return errorResponse('invalid_range', 'min must be an integer', 400, requestId);
    }
    if (rawMax !== null && maxParam === null) {
      return errorResponse('invalid_range', 'max must be an integer', 400, requestId);
    }

    const min = minParam === null ? 0 : minParam;
    const max = maxParam === null ? UINT32_MAX : maxParam;

    if (min < 0 || max < 0 || min > UINT32_MAX || max > UINT32_MAX) {
      return errorResponse('invalid_range', 'min and max must be between 0 and 4294967295', 400, requestId);
    }
    if (min > max) {
      return errorResponse('invalid_range', 'min cannot be greater than max', 400, requestId);
    }

    const value = randomInt(min, max);
    return respond({ min, max, value });
  }

  if (path === '/api/hash') {
    if (method !== 'GET') return errorResponse('method_not_allowed', 'Only GET is supported', 405, requestId);
    const params = url.searchParams;
    const input = params.get('input') || randomId(16);
    const salt = params.get('salt') || randomId(12);
    const combined = `${salt}:${input}`;
    const hash = await sha256Hex(combined);
    return respond({ algorithm: 'SHA-256', input, salt, hash, encoding: 'hex' });
  }

  if (path === '/api/uuid') {
    if (method !== 'GET') return errorResponse('method_not_allowed', 'Only GET is supported', 405, requestId);
    const uuid = crypto.randomUUID();
    return respond({ uuid });
  }

  if (path === '/api/shortid') {
    if (method !== 'GET') return errorResponse('method_not_allowed', 'Only GET is supported', 405, requestId);
    const id = shortId();
    return respond({ id });
  }

  if (path === '/api/redirect') {
    if (method !== 'GET') return errorResponse('method_not_allowed', 'Only GET is supported', 405, requestId);
    const target = url.searchParams.get('url');
    if (!isNonEmptyString(target)) {
      return errorResponse('invalid_url', 'url is required', 400, requestId);
    }
    let parsed;
    try {
      parsed = new URL(target);
    } catch (error) {
      return errorResponse('invalid_url', 'url must be a valid absolute URL', 400, requestId);
    }
    if (!/^https?:$/.test(parsed.protocol)) {
      return errorResponse('invalid_url', 'only http and https are allowed', 400, requestId);
    }
    return new Response(null, {
      status: 302,
      headers: { Location: parsed.toString(), ...cacheControlNoStore },
    });
  }

  if (path === '/api/base64/encode') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const check = requiredString(body.value?.text, 'text');
    if (!check.ok) return errorResponse('invalid_text', check.message, 400, requestId);
    const base64 = base64Encode(check.value);
    return respond({ base64 });
  }

  if (path === '/api/base64/decode') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const check = requiredString(body.value?.base64, 'base64');
    if (!check.ok) return errorResponse('invalid_base64', check.message, 400, requestId);
    const decoded = base64Decode(check.value);
    if (decoded === null) return errorResponse('invalid_base64', 'base64 is malformed', 400, requestId);
    return respond({ text: decoded });
  }

  if (path === '/api/url/encode') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const check = requiredString(body.value?.text, 'text');
    if (!check.ok) return errorResponse('invalid_text', check.message, 400, requestId);
    return respond({ encoded: encodeURIComponent(check.value) });
  }

  if (path === '/api/url/decode') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const check = requiredString(body.value?.encoded, 'encoded');
    if (!check.ok) return errorResponse('invalid_encoded', check.message, 400, requestId);
    try {
      return respond({ text: decodeURIComponent(check.value) });
    } catch (error) {
      return errorResponse('invalid_encoded', 'encoded string is malformed', 400, requestId);
    }
  }

  if (path === '/api/hex/encode') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const check = requiredString(body.value?.text, 'text');
    if (!check.ok) return errorResponse('invalid_text', check.message, 400, requestId);
    return respond({ hex: hexEncode(check.value) });
  }

  if (path === '/api/hex/decode') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const check = requiredString(body.value?.hex, 'hex');
    if (!check.ok) return errorResponse('invalid_hex', check.message, 400, requestId);
    const decoded = hexDecode(check.value);
    if (decoded === null) return errorResponse('invalid_hex', 'hex must be even length and valid characters', 400, requestId);
    return respond({ text: decoded });
  }

  if (path === '/api/json/format') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const check = requiredString(body.value?.json, 'json');
    if (!check.ok) return errorResponse('invalid_json', check.message, 400, requestId);
    try {
      const parsed = JSON.parse(check.value);
      const formatted = JSON.stringify(parsed, null, 2);
      return respond({
        formatted,
        bytes_in: new TextEncoder().encode(check.value).byteLength,
        bytes_out: new TextEncoder().encode(formatted).byteLength,
      });
    } catch (error) {
      return errorResponse('invalid_json', 'json is not valid', 400, requestId);
    }
  }

  if (path === '/api/json/minify') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const check = requiredString(body.value?.json, 'json');
    if (!check.ok) return errorResponse('invalid_json', check.message, 400, requestId);
    try {
      const parsed = JSON.parse(check.value);
      const minified = JSON.stringify(parsed);
      return respond({
        minified,
        bytes_in: new TextEncoder().encode(check.value).byteLength,
        bytes_out: new TextEncoder().encode(minified).byteLength,
      });
    } catch (error) {
      return errorResponse('invalid_json', 'json is not valid', 400, requestId);
    }
  }

  if (path === '/api/json/validate') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const check = requiredString(body.value?.json, 'json');
    if (!check.ok) return errorResponse('invalid_json', check.message, 400, requestId);
    try {
      JSON.parse(check.value);
      return respond({ valid: true });
    } catch (error) {
      const message = typeof error?.message === 'string' ? error.message : 'Invalid JSON';
      const positionMatch = message.match(/position (\d+)/i);
      const position = positionMatch ? Number(positionMatch[1]) : null;
      return respond({ valid: false, error: { message, position } });
    }
  }

  if (path === '/api/hmac') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const textCheck = requiredString(body.value?.text, 'text');
    if (!textCheck.ok) return errorResponse('invalid_text', textCheck.message, 400, requestId);
    const keyCheck = requiredString(body.value?.key, 'key');
    if (!keyCheck.ok) return errorResponse('invalid_key', keyCheck.message, 400, requestId);
    const textBytes = utf8ToBytes(textCheck.value);
    const keyBytes = utf8ToBytes(keyCheck.value);
    const sizeCheck = guardSize(textBytes.byteLength + keyBytes.byteLength);
    if (!sizeCheck.ok) return errorResponse('invalid_body', sizeCheck.message, 400, requestId);

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, textBytes);
    const sigBytes = new Uint8Array(signature);
    const hmacHex = Array.from(sigBytes, (b) => b.toString(16).padStart(2, '0')).join('');
    return respond({
      algorithm: 'HMAC-SHA256',
      hmac: hmacHex,
      bytes: { in: textBytes.byteLength + keyBytes.byteLength, out: sigBytes.byteLength },
    });
  }

  if (path === '/api/jwt/decode') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const tokenCheck = requiredString(body.value?.jwt, 'jwt');
    if (!tokenCheck.ok) return errorResponse('invalid_jwt', tokenCheck.message, 400, requestId);
    const parts = tokenCheck.value.split('.');
    if (parts.length < 2) return errorResponse('invalid_jwt', 'jwt must include header and payload', 400, requestId);
    const [headerB64, payloadB64, signatureB64 = ''] = parts;

    const headerJson = base64UrlDecode(headerB64);
    if (headerJson === null) return errorResponse('invalid_jwt', 'header is not valid base64url', 400, requestId);
    const payloadJson = base64UrlDecode(payloadB64);
    if (payloadJson === null) return errorResponse('invalid_jwt', 'payload is not valid base64url', 400, requestId);

    let header;
    let payload;
    try {
      header = JSON.parse(headerJson);
      payload = JSON.parse(payloadJson);
    } catch (error) {
      return errorResponse('invalid_jwt', 'jwt segments must decode to JSON', 400, requestId);
    }

    return respond({
      header,
      payload,
      signaturePresent: Boolean(signatureB64 && signatureB64.length > 0),
    });
  }

  if (path === '/api/crypto/keypair') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    return respond({
      algorithm: 'ECDSA-P256',
      publicKey: base64UrlEncode(new Uint8Array(publicKey)),
      privateKey: base64UrlEncode(new Uint8Array(privateKey)),
    });
  }

  if (path === '/api/crypto/publickey') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    return respond({
      algorithm: 'ECDSA-P256',
      publicKey: base64UrlEncode(new Uint8Array(publicKey)),
    });
  }

  if (path === '/api/validate/url') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const inputCheck = requiredString(body.value?.url, 'url');
    if (!inputCheck.ok) return errorResponse('invalid_url', inputCheck.message, 400, requestId);
    const lengthCheck = guardUrlLength(inputCheck.value);
    if (!lengthCheck.ok) return respond({ valid: false, reason: lengthCheck.message });

    let parsed;
    try {
      parsed = new URL(inputCheck.value);
    } catch (error) {
      return respond({ valid: false, reason: 'url is not absolute', normalized: null, scheme: null });
    }

    if (!/^https?:$/.test(parsed.protocol)) {
      return respond({ valid: false, reason: 'only http/https allowed', normalized: null, scheme: null });
    }

    const allowlist = parseAllowlist(env?.URL_ALLOWLIST);
    if (allowlist.length > 0 && !allowlist.includes(parsed.hostname.toLowerCase())) {
      return respond({
        valid: false,
        reason: 'hostname not allowed',
        normalized: null,
        scheme: parsed.protocol.replace(':', ''),
      });
    }

    return respond({
      valid: true,
      reason: null,
      normalized: parsed.toString(),
      scheme: parsed.protocol.replace(':', ''),
    });
  }

  if (path === '/api/validate/ip') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const inputCheck = requiredString(body.value?.ip, 'ip');
    if (!inputCheck.ok) return errorResponse('invalid_ip', inputCheck.message, 400, requestId);
    const ip = inputCheck.value;

    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    let version = null;
    if (ipv4Pattern.test(ip)) {
      const parts = ip.split('.').map((n) => Number(n));
      if (parts.every((n) => n >= 0 && n <= 255)) version = 4;
    } else if (/^[0-9a-fA-F:]+$/.test(ip) && ip.includes(':')) {
      version = 6;
    }

    return respond({ valid: version !== null, version });
  }

  if (path === '/api/dns/resolve') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    if (!boolFromEnv(env?.NETWORK_TOOLS_ENABLED)) {
      return errorResponse('feature_disabled', 'Network tools disabled. Set NETWORK_TOOLS_ENABLED=true', 403, requestId);
    }
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const nameCheck = requiredString(body.value?.name, 'name');
    if (!nameCheck.ok) return errorResponse('invalid_name', nameCheck.message, 400, requestId);
    const name = nameCheck.value.toLowerCase();
    if (name.length > 253 || !isHostname(name) || isIpLiteral(name)) {
      return errorResponse('invalid_name', 'name must be a hostname', 400, requestId);
    }

    const type = (body.value?.type || 'A').toUpperCase();
    if (!['A', 'AAAA', 'MX', 'TXT', 'CNAME'].includes(type)) {
      return errorResponse('invalid_type', 'type must be A, AAAA, MX, TXT, or CNAME', 400, requestId);
    }

    const allowlist = parseAllowlist(env?.DNS_ALLOWLIST);
    if (allowlist.length > 0 && !matchesAllowlist(name, allowlist)) {
      return errorResponse('invalid_name', 'hostname not allowed', 400, requestId);
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);
    try {
      const resp = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
        method: 'GET',
        headers: { Accept: 'application/dns-json' },
        redirect: 'error',
        signal: controller.signal,
      });
      clearTimeout(timeout);
      if (!resp.ok) return errorResponse('dns_error', 'resolver error', resp.status || 502, requestId);
      const data = await resp.json();
      const answers = Array.isArray(data?.Answer)
        ? data.Answer.map((ans) => ({ data: ans.data, ttl: ans.TTL })).filter(Boolean)
        : [];
      return respond({ name, type, answers });
    } catch (error) {
      clearTimeout(timeout);
      const code = error?.name === 'AbortError' ? 'dns_timeout' : 'dns_error';
      const status = error?.name === 'AbortError' ? 504 : 502;
      return errorResponse(code, 'resolver error', status, requestId);
    }
  }

  if (path === '/api/compress/test') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    if (!boolFromEnv(env?.NETWORK_TOOLS_ENABLED)) {
      return errorResponse('feature_disabled', 'Network tools disabled. Set NETWORK_TOOLS_ENABLED=true', 403, requestId);
    }
    const body = await readJsonBody(request, MAX_COMPRESS_TEXT * 2);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const textCheck = requiredString(body.value?.text, 'text');
    if (!textCheck.ok) return errorResponse('invalid_text', textCheck.message, 400, requestId);
    const inputBytes = utf8ToBytes(textCheck.value);
    if (inputBytes.length > MAX_COMPRESS_TEXT) {
      return errorResponse('invalid_text', 'text too long', 400, requestId);
    }

    if (typeof CompressionStream === 'undefined') {
      return errorResponse('not_supported', 'CompressionStream not available in this environment', 501, requestId);
    }

    async function compress(method) {
      try {
        const stream = new CompressionStream(method);
        const writer = stream.writable.getWriter();
        await writer.write(inputBytes);
        await writer.close();
        const compressed = await new Response(stream.readable).arrayBuffer();
        return new Uint8Array(compressed).length;
      } catch (error) {
        if (error && error.name === 'TypeError') return null;
        throw error;
      }
    }

    const gzipBytes = await compress('gzip');
    if (gzipBytes === null) {
      return errorResponse('not_supported', 'CompressionStream not available in this environment', 501, requestId);
    }
    const brotliBytes = await compress('br');
    if (brotliBytes === null) {
      return errorResponse('not_supported', 'CompressionStream not available in this environment', 501, requestId);
    }
    const originalBytes = inputBytes.length;
    const ratio = {
      gzip: Number((gzipBytes / originalBytes).toFixed(3)),
      brotli: Number((brotliBytes / originalBytes).toFixed(3)),
    };
    return respond({ originalBytes, gzipBytes, brotliBytes, ratio });
  }

  if (path === '/api/perf/benchmark') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const perfEnabled = boolFromEnv(env?.PERF_TOOLS_ENABLED);
    const allowlist = parseAllowlist(env?.PERF_ALLOWLIST);
    if (!perfEnabled || allowlist.length === 0) {
      return errorResponse('feature_disabled', 'Performance tools disabled. Set PERF_TOOLS_ENABLED=true and PERF_ALLOWLIST', 403, requestId);
    }

    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const urlInput = body.value?.url;
    const methodInput = (body.value?.method || 'GET').toUpperCase();
    if (!['GET', 'HEAD'].includes(methodInput)) {
      return errorResponse('invalid_method', 'method must be GET or HEAD', 400, requestId);
    }
    let target;
    try {
      target = new URL(urlInput);
    } catch (error) {
      return errorResponse('invalid_url', 'url must be absolute http/https', 400, requestId);
    }
    if (!/^https?:$/.test(target.protocol)) {
      return errorResponse('invalid_url', 'only http/https allowed', 400, requestId);
    }
    const host = target.hostname;
    if (host === 'localhost' || isIpLiteral(host) || isPrivateIp(host)) {
      return errorResponse('invalid_url', 'hostname not allowed', 400, requestId);
    }
    if (!matchesAllowlist(host, allowlist)) {
      return errorResponse('invalid_url', 'hostname not in allowlist', 400, requestId);
    }

    const timeoutMsRaw = Number.isFinite(Number(env?.PERF_TIMEOUT_MS)) ? Number(env.PERF_TIMEOUT_MS) : 2500;
    const timeoutMs = Math.min(Math.max(250, timeoutMsRaw), 5000);
    const maxBytesEnv = Number.isFinite(Number(env?.PROXY_MAX_BYTES)) ? Number(env.PROXY_MAX_BYTES) : MAX_PROXY_BYTES_DEFAULT;
    const maxBytes = Math.min(Math.max(1024, maxBytesEnv), MAX_PROXY_BYTES_CAP);

    const controller = new AbortController();
    const start = Date.now();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const resp = await fetch(target.toString(), {
        method: methodInput,
        redirect: 'manual',
        signal: controller.signal,
      });
      const ttfb = Date.now() - start;
      let bytesReceived = 0;
      if (resp.body && methodInput === 'GET') {
        const reader = resp.body.getReader();
        let done = false;
        while (!done) {
          const chunk = await reader.read();
          done = chunk.done;
          if (chunk.value) {
            bytesReceived += chunk.value.length;
            if (bytesReceived > maxBytes) break;
          }
        }
      }
      clearTimeout(timeout);
      const total = Date.now() - start;
      return respond({
        url: target.toString(),
        method: methodInput,
        timingsMs: { total, ttfb },
        status: resp.status,
        bytesReceived,
        redirected: resp.redirected,
      });
    } catch (error) {
      clearTimeout(timeout);
      if (error?.name === 'AbortError') {
        return errorResponse('perf_timeout', 'request timed out', 504, requestId);
      }
      return errorResponse('perf_error', 'benchmark failed', 502, requestId);
    }
  }

  if (path === '/api/ip/geolocate') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    if (!boolFromEnv(env?.GEOLOOKUP_ENABLED)) {
      return errorResponse('feature_disabled', 'Geo lookup disabled. Set GEOLOOKUP_ENABLED=true', 403, requestId);
    }
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const providedIp = body.value?.ip ? body.value.ip.toString() : null;
    const visitorIp = pickIp(request);

    if (providedIp && providedIp !== visitorIp) {
      return respond({ valid: false, reason: 'only visitor ip enrichment supported' });
    }

    const ipToUse = providedIp || visitorIp;
    const anonymizedIp = anonymizeIp(ipToUse);
    const cf = request.cf || {};
    const allowlist = parseAllowlist(env?.GEOLOOKUP_ALLOWLIST);
    if (allowlist.length > 0) {
      const country = (cf.country || '').toLowerCase();
      const colo = (cf.colo || '').toLowerCase();
      const ipLower = (ipToUse || '').toLowerCase();
      const allowed = allowlist.some(
        (entry) => entry.toLowerCase() === country || entry.toLowerCase() === colo || entry.toLowerCase() === ipLower
      );
      if (!allowed) return errorResponse('invalid_source', 'geolocate not allowed for this source', 403, requestId);
    }
    return respond({
      ip: anonymizedIp,
      country: cf.country || null,
      region: cf.region || null,
      city: cf.city || null,
      colo: cf.colo || null,
      asn: cf.asn || null,
      asOrganization: cf.asOrganization || null,
    });
  }

  if (path === '/api/proxy') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const master = boolFromEnv(env?.HIGH_RISK_ENABLED);
    const enabled = boolFromEnv(env?.PROXY_ENABLED);
    const allowlist = parseAllowlist(env?.PROXY_ALLOWLIST);
    if (!master || !enabled || allowlist.length === 0) {
      return errorResponse('feature_disabled', 'Proxy disabled. Enable HIGH_RISK_ENABLED and PROXY flags', 403, requestId);
    }
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const urlInput = body.value?.url;
    const methodInput = (body.value?.method || 'GET').toUpperCase();
    const safeMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'];
    if (!safeMethods.includes(methodInput)) {
      return errorResponse('invalid_method', 'method not allowed', 400, requestId);
    }
    let target;
    try {
      target = new URL(urlInput);
    } catch (error) {
      return errorResponse('invalid_url', 'url must be absolute http/https', 400, requestId);
    }
    if (!/^https?:$/.test(target.protocol)) return errorResponse('invalid_url', 'only http/https allowed', 400, requestId);
    const host = target.hostname;
    if (host === 'localhost' || host.endsWith('.local') || isIpLiteral(host) || isPrivateIp(host)) {
      return errorResponse('invalid_url', 'hostname not allowed', 400, requestId);
    }
    if (!matchesAllowlist(host, allowlist)) {
      return errorResponse('invalid_url', 'hostname not in allowlist', 400, requestId);
    }

    const headerAllow = ['accept', 'content-type', 'authorization', 'user-agent'];
    const outgoingHeaders = {};
    const inputHeaders = body.value?.headers || {};
    if (inputHeaders && typeof inputHeaders === 'object' && !Array.isArray(inputHeaders)) {
      Object.entries(inputHeaders).forEach(([k, v]) => {
        const keyLower = k.toLowerCase();
        if (headerAllow.includes(keyLower)) outgoingHeaders[keyLower] = v;
      });
    }

    const timeoutMsRaw = Number.isFinite(Number(env?.PROXY_TIMEOUT_MS)) ? Number(env.PROXY_TIMEOUT_MS) : 2500;
    const timeoutMs = Math.min(Math.max(250, timeoutMsRaw), 5000);
    const maxBytesEnv = Number.isFinite(Number(env?.PROXY_MAX_BYTES)) ? Number(env.PROXY_MAX_BYTES) : MAX_PROXY_BYTES_DEFAULT;
    const maxBytes = Math.min(Math.max(1024, maxBytesEnv), MAX_PROXY_BYTES_CAP);

    let bodyInit;
    if (body.value?.body && typeof body.value.body === 'string') {
      const bodyBytes = utf8ToBytes(body.value.body);
      const sizeCheck = guardSize(bodyBytes.length, 64 * 1024);
      if (!sizeCheck.ok) return errorResponse('invalid_body', sizeCheck.message, 400, requestId);
      bodyInit = body.value.body;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const resp = await fetch(target.toString(), {
        method: methodInput,
        headers: outgoingHeaders,
        body: ['GET', 'HEAD'].includes(methodInput) ? undefined : bodyInit,
        redirect: 'manual',
        signal: controller.signal,
      });
      clearTimeout(timeout);
      const safeHeaders = {};
      const hop = ['set-cookie', 'connection', 'upgrade', 'transfer-encoding', 'proxy-authenticate'];
      resp.headers.forEach((v, k) => {
        if (!hop.includes(k.toLowerCase())) safeHeaders[k] = v;
      });

      let bytesReceived = 0;
      let text = '';
      if (resp.body) {
        const reader = resp.body.getReader();
        let done = false;
        const chunks = [];
        while (!done) {
          const chunk = await reader.read();
          done = chunk.done;
          if (chunk.value) {
            bytesReceived += chunk.value.length;
            if (bytesReceived <= maxBytes) chunks.push(chunk.value);
            if (bytesReceived > maxBytes) break;
          }
        }
        const merged = chunks.length ? new Uint8Array(chunks.reduce((acc, c) => acc + c.length, 0)) : new Uint8Array();
        if (chunks.length) {
          let offset = 0;
          chunks.forEach((c) => {
            merged.set(c, offset);
            offset += c.length;
          });
          text = new TextDecoder().decode(merged);
        }
      }

      return respond({
        url: target.toString(),
        status: resp.status,
        ok: resp.ok,
        headers: safeHeaders,
        bytesReceived,
        bodyText: text,
        truncated: bytesReceived > maxBytes,
      });
    } catch (error) {
      clearTimeout(timeout);
      if (error?.name === 'AbortError') return errorResponse('proxy_timeout', 'proxy timed out', 504, requestId);
      return errorResponse('proxy_error', 'proxy failed', 502, requestId);
    }
  }

  if (path === '/api/mock') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const master = boolFromEnv(env?.HIGH_RISK_ENABLED);
    const enabled = boolFromEnv(env?.MOCK_ENABLED);
    if (!master || !enabled) {
      return errorResponse('feature_disabled', 'Mock disabled. Enable HIGH_RISK_ENABLED and MOCK_ENABLED', 403, requestId);
    }
    const body = await readJsonBody(request, 32 * 1024);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const schema = body.value?.schema;
    if (!schema || typeof schema !== 'object') return errorResponse('invalid_schema', 'schema required', 400, requestId);

    const maxDepthRaw = Number.isFinite(Number(env?.MOCK_MAX_DEPTH)) ? Number(env.MOCK_MAX_DEPTH) : 6;
    const maxDepth = Math.min(Math.max(1, maxDepthRaw), 10);
    const maxItemsRaw = Number.isFinite(Number(env?.MOCK_MAX_ITEMS)) ? Number(env.MOCK_MAX_ITEMS) : 100;
    const maxItems = Math.min(Math.max(1, maxItemsRaw), 500);

    let itemsUsed = 0;
    function gen(node, depth) {
      if (depth > maxDepth) return null;
      if (itemsUsed > maxItems) return null;
      const type = node.type;
      if (!type) return null;
      if (node.enum && Array.isArray(node.enum) && node.enum.length > 0) {
        return node.enum[0];
      }
      switch (type) {
        case 'string': {
          const minL = Math.max(0, node.minLength || 0);
          const maxL = Math.min(32, node.maxLength || 16);
          const len = Math.min(maxL, Math.max(minL, 8));
          return 'x'.repeat(len);
        }
        case 'number': {
          const min = Number.isFinite(node.min) ? node.min : 0;
          const max = Number.isFinite(node.max) ? node.max : min + 100;
          return min <= max ? min : 0;
        }
        case 'boolean':
          return true;
        case 'array': {
          const arr = [];
          const count = Math.min(3, maxItems - itemsUsed);
          itemsUsed += count;
          for (let i = 0; i < count; i += 1) {
            arr.push(gen(node.items || { type: 'string' }, depth + 1));
          }
          return arr;
        }
        case 'object': {
          const out = {};
          const props = node.properties || {};
          Object.entries(props).forEach(([key, val]) => {
            itemsUsed += 1;
            out[key] = gen(val, depth + 1);
          });
          return out;
        }
        default:
          return null;
      }
    }

    const data = gen(schema, 0);
    return respond({ data });
  }

  if (path === '/api/schema/validate') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const master = boolFromEnv(env?.HIGH_RISK_ENABLED);
    const enabled = boolFromEnv(env?.SCHEMA_VALIDATE_ENABLED);
    if (!master || !enabled) {
      return errorResponse('feature_disabled', 'Schema validate disabled. Enable HIGH_RISK_ENABLED and SCHEMA_VALIDATE_ENABLED', 403, requestId);
    }
    const body = await readJsonBody(request, 32 * 1024);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const schema = body.value?.schema;
    if (!schema || typeof schema !== 'object') return errorResponse('invalid_schema', 'schema required', 400, requestId);
    const data = body.value?.data;

    const maxDepthRaw = Number.isFinite(Number(env?.SCHEMA_MAX_DEPTH)) ? Number(env.SCHEMA_MAX_DEPTH) : 10;
    const maxDepth = Math.min(Math.max(1, maxDepthRaw), 20);
    const maxErrors = 50;

    const errors = [];

    function validate(node, value, path, depth) {
      if (depth > maxDepth) {
        errors.push({ path, code: 'depth_exceeded', message: 'schema depth exceeded' });
        return;
      }
      const type = node?.type;
      if (!type) {
        errors.push({ path, code: 'type_missing', message: 'type required' });
        return;
      }
      if (type === 'object') {
        if (value === null || typeof value !== 'object' || Array.isArray(value)) {
          errors.push({ path, code: 'type_mismatch', message: 'expected object' });
          return;
        }
        const props = node.properties || {};
        Object.entries(props).forEach(([key, child]) => {
          validate(child, value[key], `${path}${path ? '.' : ''}${key}`, depth + 1);
        });
        const required = Array.isArray(node.required) ? node.required : [];
        required.forEach((key) => {
          if (!(key in value)) errors.push({ path: `${path}${path ? '.' : ''}${key}`, code: 'required', message: 'missing required field' });
        });
      } else if (type === 'array') {
        if (!Array.isArray(value)) {
          errors.push({ path, code: 'type_mismatch', message: 'expected array' });
          return;
        }
        const items = node.items || { type: 'string' };
        value.forEach((v, idx) => {
          validate(items, v, `${path}[${idx}]`, depth + 1);
        });
      } else if (type === 'string') {
        if (typeof value !== 'string') errors.push({ path, code: 'type_mismatch', message: 'expected string' });
        if (typeof node.minLength === 'number' && value.length < node.minLength) {
          errors.push({ path, code: 'minLength', message: `minLength ${node.minLength}` });
        }
        if (typeof node.maxLength === 'number' && value.length > node.maxLength) {
          errors.push({ path, code: 'maxLength', message: `maxLength ${node.maxLength}` });
        }
        if (node.enum && Array.isArray(node.enum) && !node.enum.includes(value)) {
          errors.push({ path, code: 'enum', message: 'value not in enum' });
        }
      } else if (type === 'number') {
        if (typeof value !== 'number') errors.push({ path, code: 'type_mismatch', message: 'expected number' });
        if (typeof node.min === 'number' && value < node.min) errors.push({ path, code: 'min', message: `min ${node.min}` });
        if (typeof node.max === 'number' && value > node.max) errors.push({ path, code: 'max', message: `max ${node.max}` });
      } else if (type === 'boolean') {
        if (typeof value !== 'boolean') errors.push({ path, code: 'type_mismatch', message: 'expected boolean' });
      } else {
        errors.push({ path, code: 'type_unsupported', message: 'type not supported' });
      }
      if (errors.length >= maxErrors) return;
    }

    validate(schema, data, '', 0);
    const valid = errors.length === 0;
    return respond({ valid, errors: errors.slice(0, maxErrors) });
  }

  if (path === '/api/vuln/scan') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const master = boolFromEnv(env?.HIGH_RISK_ENABLED);
    const enabled = boolFromEnv(env?.VULN_SCAN_ENABLED);
    if (!master || !enabled) {
      return errorResponse('feature_disabled', 'Vuln scan disabled. Enable HIGH_RISK_ENABLED and VULN_SCAN_ENABLED', 403, requestId);
    }
    const maxTextEnv = Number.isFinite(Number(env?.VULN_MAX_TEXT)) ? Number(env.VULN_MAX_TEXT) : MAX_VULN_TEXT_DEFAULT;
    const maxText = Math.min(Math.max(1024, maxTextEnv), MAX_VULN_TEXT_CAP);
    const body = await readJsonBody(request, maxText * 2);
    if (body.error) {
      const message = String(body.error);
      if (message.toLowerCase().includes('too large')) {
        return errorResponse('invalid_text', message, 400, requestId);
      }
      return errorResponse('invalid_body', body.error, 400, requestId);
    }
    const textCheck = requiredString(body.value?.text, 'text');
    if (!textCheck.ok) return errorResponse('invalid_text', textCheck.message, 400, requestId);
    const text = textCheck.value;
    if (utf8ToBytes(text).length > maxText) return errorResponse('invalid_text', 'text too long', 400, requestId);

    const findings = [];
    const patterns = [
      { type: 'xss', severity: 'medium', regex: /<script[\s>]/i },
      { type: 'sql_injection', severity: 'high', regex: /('|")[\s]*?(or|and)[\s]+1=1/i },
      { type: 'secret', severity: 'high', regex: /api[_-]?key|secret/i },
    ];
    patterns.forEach((p) => {
      const m = text.match(p.regex);
      if (m) findings.push({ type: p.type, severity: p.severity, evidence: m[0] });
    });

    return respond({ findings });
  }

  if (path === '/api/playground') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const master = boolFromEnv(env?.HIGH_RISK_ENABLED);
    const enabled = boolFromEnv(env?.PLAYGROUND_ENABLED);
    if (!master || !enabled) {
      return errorResponse('feature_disabled', 'Playground disabled. Enable HIGH_RISK_ENABLED and PLAYGROUND_ENABLED', 403, requestId);
    }
    const body = await readJsonBody(request, 16 * 1024);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const mode = body.value?.mode;
    if (!['echo', 'json'].includes(mode)) return errorResponse('invalid_mode', 'mode must be echo or json', 400, requestId);
    if (mode === 'echo') {
      const payload = body.value?.payload;
      const preview = typeof payload === 'string' ? payload.slice(0, 200) : JSON.stringify(payload).slice(0, 200);
      return respond({ mode, received: { type: typeof payload, preview } });
    }
    if (mode === 'json') {
      const payload = body.value?.payload;
      try {
        const parsed = typeof payload === 'string' ? JSON.parse(payload) : payload;
        const formatted = JSON.stringify(parsed, null, 2);
        return respond({ mode, valid: true, formatted });
      } catch (error) {
        return respond({ mode, valid: false, reason: 'invalid_json' });
      }
    }
  }

  if (path === '/api/text/slug') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    const body = await readJsonBody(request, 16 * 1024);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const textCheck = requiredString(body.value?.text, 'text');
    if (!textCheck.ok) return errorResponse('invalid_text', textCheck.message, 400, requestId);
    const source = textCheck.value.trim();
    if (utf8ToBytes(source).length > MAX_SLUG_TEXT) {
      return errorResponse('invalid_text', 'text too long', 400, requestId);
    }
    const normalized = source.normalize('NFKD').replace(/[\u0300-\u036f]/g, '');
    const slug = normalized
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, '')
      .replace(/[\s_-]+/g, '-')
      .replace(/^-+|-+$/g, '');
    return respond({ slug, sourceLength: source.length, slugLength: slug.length });
  }

  if (path === '/api/qrcode') {
    const handleQr = (payload) => {
      const textCheck = requiredString(payload?.text, 'text');
      if (!textCheck.ok) return errorResponse('invalid_text', textCheck.message, 400, requestId);

      const eccInput = (payload?.ecc || 'M').toUpperCase();
      if (!['L', 'M', 'Q', 'H'].includes(eccInput)) {
        return errorResponse('invalid_ecc', 'ecc must be one of L, M, Q, H', 400, requestId);
      }

      const scaleRaw = payload?.scale;
      const marginRaw = payload?.margin;
      const scale = Number.isInteger(scaleRaw) ? scaleRaw : 6;
      const margin = Number.isInteger(marginRaw) ? marginRaw : 4;
      if (scale < 4 || scale > 12) return errorResponse('invalid_scale', 'scale must be between 4 and 12', 400, requestId);
      if (margin < 0 || margin > 8) return errorResponse('invalid_margin', 'margin must be between 0 and 8', 400, requestId);

      const textBytes = utf8ToBytes(textCheck.value);
      if (textBytes.length > 1024) {
        return errorResponse('invalid_text', 'text too long', 400, requestId);
      }

      const qr = generateQrSvg(textCheck.value, eccInput, scale, margin);
      if (!qr) return errorResponse('invalid_text', 'unable to encode text into QR', 400, requestId);

      return respond({ svg: qr.svg, ecc: eccInput, scale, margin, modules: qr.modules });
    };

    if (method === 'GET') {
      const params = url.searchParams;
      return handleQr({
        text: params.get('text') || 'https://example.com',
        ecc: params.get('ecc') || 'M',
        scale: parseInteger(params.get('scale')) ?? 8,
        margin: parseInteger(params.get('margin')) ?? 2,
      });
    }

    if (method !== 'POST') return methodNotAllowedWithHints(path, requestId, url, config);
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    return handleQr(body.value);
  }

  if (path === '/api/regex/test') {
    const handleRegex = (payload) => {
      const patternCheck = requiredString(payload?.pattern, 'pattern');
      if (!patternCheck.ok) return errorResponse('invalid_pattern', patternCheck.message, 400, requestId);
      if (patternCheck.value.length > MAX_REGEX_PATTERN) {
        return errorResponse('invalid_pattern', 'pattern too long', 400, requestId);
      }
      const text = (payload?.text ?? '').toString();
      if (text.length > MAX_REGEX_TEXT) {
        return errorResponse('invalid_text', 'text too long', 400, requestId);
      }
      const flags = payload?.flags || '';
      if (!/^[gimsuy]*$/.test(flags)) {
        return errorResponse('invalid_flags', 'flags must be any of g i m s u y', 400, requestId);
      }

      let regex;
      try {
        regex = new RegExp(patternCheck.value, flags);
      } catch (error) {
        return errorResponse('invalid_pattern', 'pattern failed to compile', 400, requestId);
      }

      const matches = [];
      if (regex.global) {
        let m;
        while ((m = regex.exec(text)) !== null) {
          matches.push({ match: m[0], index: m.index, groups: m.slice(1) });
          if (m[0] === '') {
            regex.lastIndex += 1;
            if (regex.lastIndex > text.length) break;
          }
        }
      } else {
        const m = regex.exec(text);
        if (m) matches.push({ match: m[0], index: m.index, groups: m.slice(1) });
      }

      return respond({ ok: true, matches, count: matches.length });
    };

    if (method === 'GET') {
      const params = url.searchParams;
      return handleRegex({
        pattern: params.get('pattern') || 'hello',
        flags: params.get('flags') || 'i',
        text: params.get('text') || 'Hello world',
      });
    }

    if (method !== 'POST') return methodNotAllowedWithHints(path, requestId, url, config);
    const body = await readJsonBody(request, 16 * 1024);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    return handleRegex(body.value);
  }

  if (path === '/api/lorem') {
    const handleLorem = (payload) => {
      const clamp = (value, min, max, fallback) => {
        const num = Number.isFinite(Number(value)) ? Number(value) : fallback;
        const intVal = Math.trunc(num);
        if (intVal < min) return min;
        if (intVal > max) return max;
        return intVal;
      };

      const paragraphs = clamp(payload?.paragraphs, 1, 10, 2);
      const sentencesPerParagraph = clamp(payload?.sentencesPerParagraph, 1, 10, 3);

      const wordbank = [
        'utility',
        'edge',
        'minimal',
        'secure',
        'fast',
        'clean',
        'api',
        'crypto',
        'json',
        'text',
        'tools',
        'diagnostics',
        'request',
        'hash',
        'random',
        'safe',
        'validate',
        'encode',
        'decode',
        'lorem',
        'entropy',
        'checksum',
        'status',
      ];

      const sentence = () => {
        const words = [];
        const len = randomInt(6, 12);
        for (let i = 0; i < len; i += 1) {
          const pick = randomInt(0, wordbank.length - 1);
          words.push(wordbank[pick]);
        }
        const line = words.join(' ');
        return line.charAt(0).toUpperCase() + line.slice(1) + '.';
      };

      const paragraphsOut = [];
      for (let p = 0; p < paragraphs; p += 1) {
        const sentences = [];
        for (let s = 0; s < sentencesPerParagraph; s += 1) {
          sentences.push(sentence());
        }
        paragraphsOut.push(sentences.join(' '));
      }

      return respond({ text: paragraphsOut.join('\n\n') });
    };

    if (method === 'GET') {
      const params = url.searchParams;
      return handleLorem({
        paragraphs: parseInteger(params.get('paragraphs')),
        sentencesPerParagraph: parseInteger(params.get('sentencesPerParagraph')),
      });
    }

    if (method !== 'POST') return methodNotAllowedWithHints(path, requestId, url, config);
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    return handleLorem(body.value);
  }

  if (path === '/api/password') {
    const handlePassword = (payload) => {
      const length = Math.trunc(Number.isFinite(Number(payload?.length)) ? Number(payload.length) : 20);
      if (Number.isNaN(length) || length < 4 || length > MAX_PASSWORD_LENGTH) {
        return errorResponse('invalid_length', `length must be between 4 and ${MAX_PASSWORD_LENGTH}`, 400, requestId);
      }

      const lower = payload?.lower !== false;
      const upper = payload?.upper !== false;
      const digits = payload?.digits !== false;
      const symbols = Boolean(payload?.symbols);

      const sets = [];
      if (lower) sets.push('abcdefghijklmnopqrstuvwxyz');
      if (upper) sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
      if (digits) sets.push('0123456789');
      if (symbols) sets.push('!@#$%^&*()-_=+[]{};:,.?/`~');

      if (sets.length === 0) {
        return errorResponse('invalid_charset', 'At least one character set must be enabled', 400, requestId);
      }

      const alphabet = sets.join('');
      const alphabetSize = alphabet.length;

      const chars = [];
      sets.forEach((set) => {
        chars.push(set[randomInt(0, set.length - 1)]);
      });
      for (let i = chars.length; i < length; i += 1) {
        const pick = randomInt(0, alphabet.length - 1);
        chars.push(alphabet[pick]);
      }
      for (let i = chars.length - 1; i > 0; i -= 1) {
        const j = randomInt(0, i);
        [chars[i], chars[j]] = [chars[j], chars[i]];
      }

      const password = chars.join('');
      const estimatedEntropyBits = Math.round(length * Math.log2(alphabetSize) * 100) / 100;

      return respond({ password, length, alphabetSize, estimatedEntropyBits });
    };

    if (method === 'GET') {
      const params = url.searchParams;
      const lengthParam = parseInteger(params.get('length'));
      const flag = (key, fallback) => {
        const value = params.get(key);
        if (value === null) return fallback;
        const lowered = String(value).toLowerCase();
        return !(lowered === '0' || lowered === 'false');
      };
      return handlePassword({
        length: lengthParam ?? 20,
        lower: flag('lowercase', true),
        upper: flag('uppercase', true),
        digits: flag('numbers', true),
        symbols: flag('symbols', false),
      });
    }

    if (method !== 'POST') return methodNotAllowedWithHints(path, requestId, url, config);
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    return handlePassword(body.value);
  }

  if (path === '/api/password/hash') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    if (!boolFromEnv(env?.CRYPTO_ADV_ENABLED)) {
      return errorResponse('feature_disabled', 'Advanced crypto disabled. Set CRYPTO_ADV_ENABLED=true', 403, requestId);
    }
    const body = await readJsonBody(request);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const passwordCheck = requiredString(body.value?.password, 'password');
    if (!passwordCheck.ok) return errorResponse('invalid_password', passwordCheck.message, 400, requestId);
    const passwordBytes = utf8ToBytes(passwordCheck.value);
    if (passwordBytes.length > MAX_PASSWORD_INPUT) {
      return errorResponse('invalid_password', 'password too long', 400, requestId);
    }

    const envSalt = env?.PASSWORD_HASH_SALT;
    const saltValue = body.value?.salt ?? envSalt;
    if (!saltValue) return errorResponse('invalid_salt', 'salt required', 400, requestId);
    const saltBytes = utf8ToBytes(saltValue);
    if (saltBytes.length > 1024) return errorResponse('invalid_salt', 'salt too long', 400, requestId);

    const iterations = Number.isFinite(Number(body.value?.iterations))
      ? Number(body.value.iterations)
      : 120000;
    if (iterations < 10000 || iterations > 1000000) {
      return errorResponse('invalid_iterations', 'iterations must be between 10000 and 1000000', 400, requestId);
    }

    const length = Number.isFinite(Number(body.value?.length)) ? Number(body.value.length) : 32;
    if (length < 16 || length > 64) {
      return errorResponse('invalid_length', 'length must be between 16 and 64', 400, requestId);
    }

    const hashAlg = (body.value?.hash || 'SHA-256').toUpperCase();
    if (hashAlg !== 'SHA-256') return errorResponse('invalid_hash', 'hash must be SHA-256', 400, requestId);

    const keyMaterial = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits']);
    const derived = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
      keyMaterial,
      length * 8
    );
    const derivedKey = bytesToBase64(new Uint8Array(derived));
    const saltOut = bytesToBase64(saltBytes);

    return respond({
      algorithm: 'PBKDF2-SHA256',
      iterations,
      length,
      salt: saltOut,
      derivedKey,
    });
  }

  if (path === '/api/jwt/sign') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    if (!boolFromEnv(env?.CRYPTO_ADV_ENABLED)) {
      return errorResponse('feature_disabled', 'Advanced crypto disabled. Set CRYPTO_ADV_ENABLED=true', 403, requestId);
    }
    const secret = env?.JWT_HS256_SECRET;
    if (!secret) return errorResponse('invalid_config', 'JWT_HS256_SECRET required', 400, requestId);

    const body = await readJsonBody(request, 32 * 1024);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const payload = body.value?.payload;
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return errorResponse('invalid_payload', 'payload must be an object', 400, requestId);
    }
    const headerInput = body.value?.header;
    if (headerInput && (typeof headerInput !== 'object' || Array.isArray(headerInput))) {
      return errorResponse('invalid_header', 'header must be an object', 400, requestId);
    }
    const ttlSeconds = Number.isFinite(Number(body.value?.ttlSeconds)) ? Number(body.value.ttlSeconds) : 3600;
    if (ttlSeconds < 60 || ttlSeconds > 86400) {
      return errorResponse('invalid_ttl', 'ttlSeconds must be between 60 and 86400', 400, requestId);
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const payloadWithExp = { ...payload };
    if (!payloadWithExp.exp) payloadWithExp.exp = nowSec + ttlSeconds;
    if (!payloadWithExp.iat) payloadWithExp.iat = nowSec;

    const header = { alg: 'HS256', typ: 'JWT', ...(headerInput || {}) };
    if (header.alg !== 'HS256') return errorResponse('invalid_header', 'alg must be HS256', 400, requestId);

    const encoder = new TextEncoder();
    const secretKey = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
      'sign',
    ]);

    const encodedHeader = base64UrlEncode(utf8ToBytes(JSON.stringify(header)));
    const encodedPayload = base64UrlEncode(utf8ToBytes(JSON.stringify(payloadWithExp)));
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signatureBuf = await crypto.subtle.sign('HMAC', secretKey, encoder.encode(signingInput));
    const signature = base64UrlEncode(new Uint8Array(signatureBuf));
    const jwt = `${encodedHeader}.${encodedPayload}.${signature}`;

    return respond({ jwt });
  }

  if (path === '/api/jwt/verify') {
    const guard = postOnlyGuard(method, path, requestId, url, config);
    if (guard) return guard;
    if (!boolFromEnv(env?.CRYPTO_ADV_ENABLED)) {
      return errorResponse('feature_disabled', 'Advanced crypto disabled. Set CRYPTO_ADV_ENABLED=true', 403, requestId);
    }
    const secret = env?.JWT_HS256_SECRET;
    if (!secret) return errorResponse('invalid_config', 'JWT_HS256_SECRET required', 400, requestId);

    const body = await readJsonBody(request, 16 * 1024);
    if (body.error) return errorResponse('invalid_body', body.error, 400, requestId);
    const tokenCheck = requiredString(body.value?.jwt, 'jwt');
    if (!tokenCheck.ok) return errorResponse('invalid_jwt', tokenCheck.message, 400, requestId);
    if (tokenCheck.value.length > MAX_JWT_LENGTH) {
      return errorResponse('invalid_jwt', 'jwt too long', 400, requestId);
    }

    const parts = tokenCheck.value.split('.');
    if (parts.length !== 3) return respond({ valid: false, reason: 'invalid_format' });

    const [h, p, sig] = parts;
    const headerJson = base64UrlDecode(h);
    const payloadJson = base64UrlDecode(p);
    if (headerJson === null || payloadJson === null) return respond({ valid: false, reason: 'invalid_encoding' });

    let header;
    let payload;
    try {
      header = JSON.parse(headerJson);
      payload = JSON.parse(payloadJson);
    } catch (error) {
      return respond({ valid: false, reason: 'invalid_json' });
    }

    if (header.alg !== 'HS256') {
      return respond({ valid: false, reason: 'unsupported_alg', header, payload });
    }

    const encoder = new TextEncoder();
    const secretKey = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
      'verify',
    ]);
    const signingInput = `${h}.${p}`;
    const signatureBytes = base64UrlToBytes(sig);
    if (!signatureBytes) return respond({ valid: false, reason: 'invalid_signature_encoding', header, payload });
    const isValid = await crypto.subtle.verify('HMAC', secretKey, signatureBytes, encoder.encode(signingInput));
    if (!isValid) return respond({ valid: false, reason: 'signature_mismatch', header, payload });

    const nowSec = Math.floor(Date.now() / 1000);
    if (typeof payload.nbf === 'number' && payload.nbf > nowSec) {
      return respond({ valid: false, reason: 'nbf_not_met', header, payload });
    }
    if (typeof payload.exp === 'number' && payload.exp < nowSec) {
      return respond({ valid: false, reason: 'expired', header, payload });
    }

    return respond({ valid: true, header, payload });
  }

  return errorResponse('not_found', 'Endpoint not found', 404, requestId);
}
