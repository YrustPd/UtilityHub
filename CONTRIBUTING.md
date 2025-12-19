# Contributing

Thanks for helping improve UtilityHub. Please keep changes focused and consistent with the current minimal, security-first scope.

## Scope and discipline
- Keep the Worker lightweight and fast.
- Avoid adding new dependencies unless strictly necessary.
- Preserve the unified JSON error schema and requestId behavior.
- Maintain feature gating for advanced and high-risk tools.

## Development
- Node 20+ recommended.
- Install dependencies: npm install
- Run tests: npm test
- Local dev: npx wrangler dev

## Code style
- Follow existing patterns and file organization.
- Prefer small, targeted diffs over refactors.
- Keep security headers, CSP, and input validation intact.

## Security-sensitive areas
Changes that touch any of the following require extra scrutiny:
- Outbound fetch tools (proxy, perf, DNS, geolocate)
- High-risk endpoints (mock, schema validate, vuln scan, playground)
- Rate limiting behavior and configuration
- Logging or any data exposure

## Change checklist
- Tests pass (npm test)
- Docs updated for any behavior or config changes
- High-risk changes reviewed for abuse and SSRF risks
- No new dependencies without justification
