# UtilityHub

UtilityHub is a Cloudflare Worker utility hub that serves a fast UI and a JSON API for diagnostics and developer utilities.

## Overview
- Single Worker serving UI and API.
- Stateless (no persistent storage).
- Strict security headers and CSP by default.
- Unified JSON error schema with requestId on all API responses.

## Endpoints

Diagnostics
- GET /health
- GET /api/status
- GET /api/ping
- GET /api/trace

Identity and request
- GET /api/whoami
- GET /api/ip
- GET /api/headers
- GET /api/useragent

Time, random, and IDs
- GET /api/time
- GET /api/random
- GET /api/hash
- GET /api/uuid
- GET /api/shortid
- GET /api/redirect

Encoding and decoding (POST JSON)
- POST /api/base64/encode
- POST /api/base64/decode
- POST /api/url/encode
- POST /api/url/decode
- POST /api/hex/encode
- POST /api/hex/decode

JSON tools (POST JSON)
- POST /api/json/format
- POST /api/json/minify
- POST /api/json/validate

Crypto helpers (POST JSON)
- POST /api/hmac
- POST /api/jwt/decode
- POST /api/crypto/keypair
- POST /api/crypto/publickey

Text and utility tools
- GET or POST /api/regex/test
- GET or POST /api/lorem
- POST /api/text/slug
- GET or POST /api/password
- GET or POST /api/qrcode

Validation (POST JSON)
- POST /api/validate/url
- POST /api/validate/ip

Advanced crypto (requires CRYPTO_ADV_ENABLED=true)
- POST /api/password/hash
- POST /api/jwt/sign
- POST /api/jwt/verify

Network and performance (gated)
- POST /api/dns/resolve (NETWORK_TOOLS_ENABLED)
- POST /api/compress/test (NETWORK_TOOLS_ENABLED)
- POST /api/perf/benchmark (PERF_TOOLS_ENABLED and PERF_ALLOWLIST)
- POST /api/ip/geolocate (GEOLOOKUP_ENABLED)

High risk (requires HIGH_RISK_ENABLED=true and per-tool flags)
- POST /api/proxy (PROXY_ENABLED and PROXY_ALLOWLIST)
- POST /api/mock (MOCK_ENABLED)
- POST /api/schema/validate (SCHEMA_VALIDATE_ENABLED)
- POST /api/vuln/scan (VULN_SCAN_ENABLED)
- POST /api/playground (PLAYGROUND_ENABLED)

## UI behavior
- Click a path to copy it (toast confirmation).
- Click a card to open the endpoint in a new tab (same origin only).
- Mobile sections are collapsible and remember state.
- Advanced and high-risk sections are separated and disabled by default.

## Quick Start (root mode)
- See docs/DEPLOYMENT.md for full steps.
- Run Wrangler dev and open /health and /api/status.

## Attach to existing Worker (prefix mode)
- See docs/DEPLOYMENT.md and adapter-snippet.js for Service Binding routing.

## Deployment
- Install: npm install
- Local dev: npx wrangler dev
- Publish: npx wrangler deploy

## Prefix handling
- HUB_PREFIX sets the base path (default: /).
- If you deploy under a path (for example /hub), set HUB_PREFIX=/hub.
- When HUB_PREFIX=/, the Worker infers a safe prefix from the request path when possible.

## Configuration
- Configuration reference: docs/CONFIGURATION.md
- Troubleshooting: docs/TROUBLESHOOTING.md


Core
| Variable | Default | Notes |
| --- | --- | --- |
| HUB_NAME | UtilityHub | UI and status name |
| HUB_TAGLINE | Minimal edge utilities | UI tagline |
| HUB_VERSION | 1.0.0 | UI and /api/status version |
| HUB_PREFIX | / | Base path for UI and API |
| LOGGING_ENABLED | false | Minimal request logging (no headers or bodies) |

Rate limiting
| Variable | Default | Notes |
| --- | --- | --- |
| RATE_LIMIT_ENABLED | false | Enable rate limiting |
| RATE_LIMIT_BACKEND | auto | auto, kv, or do |
| RATE_LIMIT_WINDOW_SEC | 60 | Sliding window size |
| RATE_LIMIT_MAX | 60 | Default limit per window |
| RATE_LIMIT_MAX_CRYPTO | 20 | Stricter limit for heavier routes |
| RATE_LIMIT_KV | binding | KV namespace binding |
| RATE_LIMIT_DO | binding | Durable Object binding |

Advanced crypto
| Variable | Default | Notes |
| --- | --- | --- |
| CRYPTO_ADV_ENABLED | false | Enables password hash and JWT sign/verify |
| JWT_HS256_SECRET | (none) | Required for JWT sign/verify |
| PASSWORD_HASH_SALT | (none) | Optional default salt for password hash |

Network and performance
| Variable | Default | Notes |
| --- | --- | --- |
| NETWORK_TOOLS_ENABLED | false | Enables DNS resolve and compression tests |
| DNS_ALLOWLIST | (none) | Optional hostname allowlist |
| PERF_TOOLS_ENABLED | false | Enables performance benchmark |
| PERF_ALLOWLIST | (none) | Required when perf tools are enabled |
| PERF_TIMEOUT_MS | 2500 | Min 250, max 5000 |
| GEOLOOKUP_ENABLED | false | Enables IP geolocation |
| GEOLOOKUP_ALLOWLIST | (none) | Optional source allowlist (country, colo, or IP) |

High risk
| Variable | Default | Notes |
| --- | --- | --- |
| HIGH_RISK_ENABLED | false | Master gate for high-risk tools |
| PROXY_ENABLED | false | Enables /api/proxy |
| PROXY_ALLOWLIST | (none) | Required when proxy is enabled |
| PROXY_TIMEOUT_MS | 2500 | Min 250, max 5000 |
| PROXY_MAX_BYTES | 262144 | Max response bytes (also used by perf) |
| MOCK_ENABLED | false | Enables /api/mock |
| MOCK_MAX_DEPTH | 6 | Min 1, max 10 |
| MOCK_MAX_ITEMS | 100 | Min 1, max 500 |
| SCHEMA_VALIDATE_ENABLED | false | Enables /api/schema/validate |
| SCHEMA_MAX_DEPTH | 10 | Min 1, max 20 |
| VULN_SCAN_ENABLED | false | Enables /api/vuln/scan |
| VULN_MAX_TEXT | 8192 | Min 1024, max 32768 |
| PLAYGROUND_ENABLED | false | Enables /api/playground |

URL validation allowlist
- URL_ALLOWLIST: optional hostname allowlist for /api/validate/url.

## POST endpoints
- Browser navigation is GET only. Use curl or fetch for POST endpoints.

## Security notes
- Strict security headers and CSP are applied to all responses.
- High-risk tools are off by default and must be explicitly enabled.
- Outbound tools use allowlists where required and block private/localhost targets for proxy/perf.
- Logging is minimal and off by default.

## SEO & Indexing
- Homepage is indexable.
- API routes are noindex (disallowed in robots.txt and excluded from sitemap.xml).
- Structured data (JSON-LD) is embedded in the UI.

## Troubleshooting
- Missing bindings: if RATE_LIMIT_ENABLED=true without KV or DO bindings, requests return a configuration error.
- Browser limitations: POST endpoints require a JSON body; use curl or fetch.
- Icons missing: ensure ASSETS is bound to the assets directory in wrangler.toml.

## Project Governance
- CONTRIBUTING.md
- SECURITY.md
- CODE_OF_CONDUCT.md
- RELEASE.md

## Links
- LICENSE
