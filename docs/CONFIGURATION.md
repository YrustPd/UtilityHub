# Configuration

UtilityHub is configured through environment variables and bindings. All values are optional unless noted.

## Safe defaults
- Advanced and high-risk tools are disabled by default.
- Rate limiting is disabled by default.
- Logging is disabled by default.

## Core settings

| Name | Default | Type | Example | Security notes |
| --- | --- | --- | --- | --- |
| HUB_NAME | UtilityHub | string | UtilityHub | Display name in UI and /api/status |
| HUB_TAGLINE | Minimal edge utilities | string | Minimal edge utilities | Display tagline only |
| HUB_VERSION | 1.0.0 | string | 1.0.0 | Shown in UI and /api/status |
| HUB_PREFIX | / | string | /hub | Base path for UI and API |
| LOGGING_ENABLED | false | boolean | true | Logs request line only (no headers/body) |

## Rate limiting

| Name | Default | Type | Example | Security notes |
| --- | --- | --- | --- | --- |
| RATE_LIMIT_ENABLED | false | boolean | true | Enable rate limiting |
| RATE_LIMIT_BACKEND | auto | string | kv | auto, kv, or do |
| RATE_LIMIT_WINDOW_SEC | 60 | number | 60 | Window size in seconds |
| RATE_LIMIT_MAX | 60 | number | 120 | Default limit per window |
| RATE_LIMIT_MAX_CRYPTO | 20 | number | 40 | Lower limit for heavier routes |
| RATE_LIMIT_KV | binding | KV binding | RATE_LIMIT_KV | Required if RATE_LIMIT_BACKEND=kv |
| RATE_LIMIT_DO | binding | DO binding | RATE_LIMIT_DO | Required if RATE_LIMIT_BACKEND=do |

## Advanced crypto

| Name | Default | Type | Example | Security notes |
| --- | --- | --- | --- | --- |
| CRYPTO_ADV_ENABLED | false | boolean | true | Enables password hash and JWT sign/verify |
| JWT_HS256_SECRET | (none) | string | your-secret | Required for JWT sign/verify |
| PASSWORD_HASH_SALT | (none) | string | static-salt | Optional default salt |

## Network and performance

| Name | Default | Type | Example | Security notes |
| --- | --- | --- | --- | --- |
| NETWORK_TOOLS_ENABLED | false | boolean | true | Enables DNS resolve and compression tests |
| DNS_ALLOWLIST | (none) | string | example.com,api.example.com | Restrict DNS resolve |
| PERF_TOOLS_ENABLED | false | boolean | true | Enables perf benchmark |
| PERF_ALLOWLIST | (none) | string | example.com | Required when perf is enabled |
| PERF_TIMEOUT_MS | 2500 | number | 3000 | Min 250, max 5000 |
| GEOLOOKUP_ENABLED | false | boolean | true | Enables IP geolocate |
| GEOLOOKUP_ALLOWLIST | (none) | string | us,sfo | Optional source allowlist |

## High-risk tools

| Name | Default | Type | Example | Security notes |
| --- | --- | --- | --- | --- |
| HIGH_RISK_ENABLED | false | boolean | true | Master gate for high-risk tools |
| PROXY_ENABLED | false | boolean | true | Enables /api/proxy |
| PROXY_ALLOWLIST | (none) | string | api.example.com | Required when proxy is enabled |
| PROXY_TIMEOUT_MS | 2500 | number | 3000 | Min 250, max 5000 |
| PROXY_MAX_BYTES | 262144 | number | 524288 | Max response bytes |
| MOCK_ENABLED | false | boolean | true | Enables /api/mock |
| MOCK_MAX_DEPTH | 6 | number | 6 | Min 1, max 10 |
| MOCK_MAX_ITEMS | 100 | number | 200 | Min 1, max 500 |
| SCHEMA_VALIDATE_ENABLED | false | boolean | true | Enables /api/schema/validate |
| SCHEMA_MAX_DEPTH | 10 | number | 12 | Min 1, max 20 |
| VULN_SCAN_ENABLED | false | boolean | true | Enables /api/vuln/scan |
| VULN_MAX_TEXT | 8192 | number | 12000 | Min 1024, max 32768 |
| PLAYGROUND_ENABLED | false | boolean | true | Enables /api/playground |

## URL validation allowlist

| Name | Default | Type | Example | Security notes |
| --- | --- | --- | --- | --- |
| URL_ALLOWLIST | (none) | string | example.com,api.example.com | Restricts /api/validate/url |

## Bindings

| Binding | Required | Notes |
| --- | --- | --- |
| ASSETS | recommended | Serves icons and /assets/* content |
| RATE_LIMIT_KV | optional | KV backend for rate limiting |
| RATE_LIMIT_DO | optional | DO backend for rate limiting |
