import { textResponse } from '../helpers/utils.js';

const assetCacheHeaders = { 'Cache-Control': 'public, max-age=86400, immutable' };
const iconCacheHeaders = { 'Cache-Control': 'public, max-age=31536000, immutable' };
const metaCacheHeaders = { 'Cache-Control': 'public, max-age=86400' };

function normalizePrefix(prefix) {
  if (!prefix || prefix === '/') return '';
  const trimmed = `${prefix}`.trim();
  const withLeading = trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
  return withLeading.replace(/\/+$/, '');
}

function joinSitemapUrl(origin, prefix, path = '') {
  const normalizedPrefix = normalizePrefix(prefix);
  const normalizedPath = path ? path.replace(/^\/+/, '') : '';
  if (!normalizedPrefix && !normalizedPath) return `${origin}/`;
  if (!normalizedPath) return `${origin}${normalizedPrefix}/`;
  return `${origin}${normalizedPrefix}/${normalizedPath}`;
}

async function fetchAsset(
  pathname,
  env,
  request,
  url,
  cacheHeaders = assetCacheHeaders,
  contentType
) {
  if (!env.ASSETS) return null;
  const assetRequest = new Request(new URL(pathname, url).toString(), request);
  const assetResponse = await env.ASSETS.fetch(assetRequest);
  if (assetResponse && assetResponse.ok) {
    const headers = new Headers(assetResponse.headers);
    headers.set('Cache-Control', cacheHeaders['Cache-Control']);
    if (contentType) {
      headers.set('Content-Type', contentType);
    }
    return new Response(assetResponse.body, { status: assetResponse.status, headers });
  }
  return null;
}

export async function handleStatic(request, env, ctx, meta = {}) {
  const { path, url, config } = meta;

  if (path === '/robots.txt') {
    const body = 'User-agent: *\nAllow: /\nDisallow: /api/\n';
    return textResponse(body, 200, metaCacheHeaders);
  }

  if (path === '/sitemap.xml') {
    const entries = [
      joinSitemapUrl(url.origin, config?.prefix || '/', ''),
      joinSitemapUrl(url.origin, config?.prefix || '/', 'api/status'),
    ];
    const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${entries
      .map((loc) => `  <url><loc>${loc}</loc></url>`)
      .join('\n')}\n</urlset>`;
    return new Response(xml, {
      status: 200,
      headers: {
        'Content-Type': 'application/xml; charset=UTF-8',
        ...metaCacheHeaders,
      },
    });
  }

  if (
    path === '/favicon.ico' ||
    path === '/favicon-16x16.png' ||
    path === '/favicon-32x32.png' ||
    path === '/apple-touch-icon.png'
  ) {
    const contentType = path.endsWith('.ico') ? 'image/x-icon' : 'image/png';
    const fetched = await fetchAsset(path, env, request, url, iconCacheHeaders, contentType);
    if (fetched) return fetched;
  }

  if (path.startsWith('/assets/')) {
    const resolvedPath = path.replace(/^\/assets/, '') || '/';
    const cleanedPath = resolvedPath.startsWith('/') ? resolvedPath : `/${resolvedPath}`;
    const fetched = await fetchAsset(cleanedPath, env, request, url);
    if (fetched) return fetched;
  }

  return null;
}
