# Deployment

This guide uses Wrangler only.

## Prerequisites
- Cloudflare account
- Wrangler installed

## Root mode (serve at /)
1) Set HUB_PREFIX=/ (default).
2) Configure optional bindings if needed.
3) Deploy with Wrangler.

## Prefix mode (serve under a path)
Use prefix mode when attaching UtilityHub under an existing Worker or when you want a subpath.

Examples:
- /hub
- /.well-known/utilityhub

Steps:
1) Set HUB_PREFIX to the desired path (for example /hub).
2) Configure bindings if needed.
3) Deploy with Wrangler.

## Service binding integration (concept)
If you already have a Worker and want UtilityHub to live under a prefix, use a Service Binding:
- Bind the UtilityHub Worker as UTILITYHUB in the existing Worker.
- Route only the UtilityHub prefix to the binding.
- Strip the prefix before forwarding so UtilityHub sees root paths.

See adapter-snippet.js for a minimal example.

## Optional bindings
- ASSETS: required to serve icons and any /assets/* content.
- RATE_LIMIT_KV: optional KV namespace binding.
- RATE_LIMIT_DO: optional Durable Object binding.

## Local development
- Create a .env file from .env.example (optional).
- Run Wrangler dev and verify /health and /api/status.
