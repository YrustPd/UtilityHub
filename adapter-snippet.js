// Minimal Service Binding adapter for an existing Worker.
// Routes only specific prefixes to UtilityHub and keeps all other traffic unchanged.
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const prefixes = ['/hub', '/.well-known/utilityhub'];
    const matched = prefixes.find((prefix) => url.pathname === prefix || url.pathname.startsWith(prefix + '/'));
    if (!matched) {
      return env.NEXT?.fetch ? env.NEXT.fetch(request) : new Response('Not found', { status: 404 });
    }

    if (!env.UTILITYHUB || typeof env.UTILITYHUB.fetch !== 'function') {
      return new Response(
        JSON.stringify({ error: { code: 'binding_missing', message: 'UTILITYHUB service binding is not configured' } }),
        { status: 500, headers: { 'Content-Type': 'application/json; charset=UTF-8', 'Cache-Control': 'no-store' } }
      );
    }

    // Strip the prefix so UtilityHub can operate in root mode behind the binding.
    const rewritten = new URL(request.url);
    rewritten.pathname = url.pathname.slice(matched.length) || '/';

    return env.UTILITYHUB.fetch(new Request(rewritten.toString(), request));
  },
};
