# Security Model

UtilityHub is designed for safe defaults and minimal exposure.

## Core decisions
- Stateless: no persistent storage.
- API responses are no-store.
- Strict security headers and CSP on all responses.
- Unified JSON error schema with requestId for correlation.

## Outbound safety
- Outbound tools use allowlists where required.
- Proxy and performance tools block private and localhost targets.
- High-risk tools are gated and disabled by default.

## Logging
- Logging is minimal and disabled by default.
- No request headers or bodies are logged.
