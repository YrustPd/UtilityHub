const securityHeaders = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy':
    'geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
};

export function applySecurityHeaders(response) {
  const headers = new Headers(response.headers);
  if (!headers.has('Content-Security-Policy')) {
    headers.set('Content-Security-Policy', [
      "default-src 'none'",
      "img-src 'self' data:",
      "connect-src 'self'",
      "font-src 'none'",
      "object-src 'none'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "form-action 'none'",
    ].join('; '));
  }
  headers.set('Cross-Origin-Resource-Policy', 'same-origin');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Embedder-Policy', 'require-corp');

  Object.entries(securityHeaders).forEach(([key, value]) => headers.set(key, value));

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
