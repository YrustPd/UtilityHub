# Release Checklist

## Pre-release checks
- Run npm test and confirm all tests pass.
- Run wrangler dev and verify:
  - GET /health
  - GET /api/status
  - One POST endpoint with a JSON body
- Confirm feature flags default to safe values (advanced and high-risk tools disabled).
- Confirm documentation matches current endpoints and configuration flags.

## Versioning rules
- Patch: fixes and internal changes only, no new endpoints or flags.
- Minor: backwards-compatible features (new endpoints or flags).
- Major: breaking changes (removals, incompatible changes, or behavioral changes).

## Update for a release
- Update package.json version.
- Update wrangler.toml default HUB_VERSION.
- Update any UI version display source if applicable.

## Post-release verification
- Open the deployed UI and confirm it loads correctly.
- Verify response headers (CSP and other security headers) are present.
- Check /api/status for the correct version.
- Run one GET and one POST endpoint on the deployed service.
