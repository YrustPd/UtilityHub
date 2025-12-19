import { handleApi } from './routes/api.js';
import { handleUi } from './routes/ui.js';
import { handleStatic } from './routes/static.js';
import { applySecurityHeaders } from './helpers/security.js';
import { handleError } from './middleware/error.js';
import { randomId } from './helpers/utils.js';
export { RateLimiterDO } from './rateLimiterDO.js';

const defaults = {
  name: 'UtilityHub',
  tagline: 'Minimal edge utilities',
  version: '1.0.0',
  prefix: '/',
};

function normalizePrefix(input) {
  if (!input) return '/';
  const trimmed = input.trim();
  const leading = trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
  const withoutTrailing = leading.replace(/\/+$/, '');
  return withoutTrailing === '' ? '/' : withoutTrailing;
}

function derivePrefix(pathname, envPrefix) {
  const normalized = normalizePrefix(envPrefix || '/');
  if (normalized !== '/') return normalized;
  const segments = pathname.split('/').filter(Boolean);
  if (segments.length === 0) return '/';
  const firstSegment = segments[0];
  const firstLower = firstSegment.toLowerCase();
  const reserved = new Set([
    'api',
    'health',
    'favicon.ico',
    'favicon-16x16.png',
    'favicon-32x32.png',
    'apple-touch-icon.png',
    'robots.txt',
    'sitemap.xml',
    'styles.css',
    'script.js',
    'assets',
  ]);
  if (firstSegment === '.well-known' && segments[1]) {
    return normalizePrefix(`/.well-known/${segments[1]}`);
  }
  if (reserved.has(firstLower)) return '/';
  return normalizePrefix(`/${firstSegment}`);
}

function stripPrefix(pathname, prefix) {
  if (prefix === '/') return pathname || '/';
  if (!pathname.startsWith(prefix)) return null;
  const remainder = pathname.slice(prefix.length) || '/';
  return remainder.startsWith('/') ? remainder : `/${remainder}`;
}

function isApiRoute(pathname) {
  const normalized = (pathname || '').toLowerCase();
  return normalized === '/health' || normalized.startsWith('/api/');
}

function isStaticRoute(pathname) {
  return (
    pathname === '/favicon.ico' ||
    pathname === '/favicon-16x16.png' ||
    pathname === '/favicon-32x32.png' ||
    pathname === '/apple-touch-icon.png' ||
    pathname === '/sitemap.xml' ||
    pathname === '/robots.txt' ||
    pathname === '/styles.css' ||
    pathname === '/script.js' ||
    pathname.startsWith('/assets/')
  );
}

function notFoundResponse(isApi, requestId) {
  if (isApi) {
    return new Response(
      JSON.stringify({ error: { code: 'not_found', message: 'Not found' }, requestId }),
      {
        status: 404,
        headers: { 'Content-Type': 'application/json; charset=UTF-8', 'Cache-Control': 'no-store' },
      }
    );
  }
  return new Response('Not found', { status: 404, headers: { 'Cache-Control': 'no-store' } });
}

function addRequestId(response, requestId) {
  const headers = new Headers(response.headers);
  headers.set('x-utilityhub-request-id', requestId);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export default {
  async fetch(request, env, ctx) {
    const requestId = randomId(12);
    const started = Date.now();
    const loggingEnabled = String(env.LOGGING_ENABLED || '').toLowerCase() === 'true';
    const url = new URL(request.url);
    const config = {
      name: env.HUB_NAME || defaults.name,
      tagline: env.HUB_TAGLINE || defaults.tagline,
      version: env.HUB_VERSION || defaults.version,
      prefix: derivePrefix(url.pathname, env.HUB_PREFIX || defaults.prefix),
    };

    const hostname = url.hostname;
    const localPath = stripPrefix(url.pathname, config.prefix);
    if (localPath === null) {
      const fallback = notFoundResponse(false, requestId);
      const withId = addRequestId(fallback, requestId);
      const secured = applySecurityHeaders(withId);
      if (loggingEnabled) {
        const duration = Date.now() - started;
        console.log(`${requestId} ${request.method} ${url.pathname} ${secured.status} ${duration}ms`);
      }
      return secured;
    }

    const normalizedPath = localPath ? localPath.toLowerCase() : localPath;
    const isApi = isApiRoute(normalizedPath);
    try {
      let response;

      if (isStaticRoute(localPath)) {
        response = await handleStatic(request, env, ctx, { url, hostname, path: localPath, config });
      } else if (isApi) {
        response = await handleApi(request, env, ctx, {
          url,
          hostname,
          path: normalizedPath,
          config,
          requestId,
          loggingEnabled,
        });
      } else {
        response = await handleUi(request, env, ctx, {
          url,
          hostname,
          path: localPath,
          config,
          requestId,
        });
      }

      const finalResponse = response || notFoundResponse(isApi, requestId);
      const withId = addRequestId(finalResponse, requestId);
      const secured = applySecurityHeaders(withId);
      if (loggingEnabled) {
        const duration = Date.now() - started;
        console.log(`${requestId} ${request.method} ${url.pathname} ${secured.status} ${duration}ms`);
      }
      return secured;
    } catch (error) {
      const errResponse = handleError(error, { isApi, requestId });
      const withId = addRequestId(errResponse, requestId);
      const secured = applySecurityHeaders(withId);
      if (loggingEnabled) {
        const duration = Date.now() - started;
        console.log(`${requestId} ${request.method} ${url.pathname} ${secured.status} ${duration}ms`);
      }
      return secured;
    }
  },
};
