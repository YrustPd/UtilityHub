# Troubleshooting

## UI loads but looks unstyled
Symptoms:
- UI appears without layout or missing styling.

Fix:
- Open the Worker URL served by Wrangler dev or your deployment. Do not open local files directly.

## Prefix issues
Symptoms:
- 404 for assets when using a prefix.
- Canonical URL mismatch.
- Double prefix paths in requests.

Fix:
- Set HUB_PREFIX to the exact base path (for example /hub).
- When proxying via a Service Binding, strip the prefix before forwarding.
- Verify the canonical URL in the HTML head matches the deployed path.

## POST endpoints opened in a browser
Symptoms:
- 405 method_not_allowed error.

Fix:
- POST endpoints require a JSON body. Use curl or fetch; browser navigation is GET.

## Rate limiting backend confusion (KV vs DO)
Symptoms:
- 500 configuration error when RATE_LIMIT_ENABLED=true.

Fix:
- Configure either RATE_LIMIT_KV or RATE_LIMIT_DO and set RATE_LIMIT_BACKEND accordingly.
- If you do not need rate limiting, set RATE_LIMIT_ENABLED=false.

## Feature flags disabled
Symptoms:
- 403 feature_disabled error.

Fix:
- Enable the required flag(s) in configuration. High-risk tools also require HIGH_RISK_ENABLED.

## Wrangler dev connect() timeouts
Symptoms:
- Local dev logs show connect() timeouts.

Causes and fixes:
- Outbound endpoints (proxy, perf benchmark, DNS) can trigger external fetches. Keep them disabled by default.
- Confirm flags are disabled: NETWORK_TOOLS_ENABLED=false, PERF_TOOLS_ENABLED=false, HIGH_RISK_ENABLED=false.
- Use /api/status to verify enabled flags.
