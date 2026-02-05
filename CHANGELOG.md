# Changelog

## 0.1.0

Initial release.

- JWE token decryption middleware for Starlette/MCP
- `get_user()` context accessor for authenticated claims
- Public JWKS endpoint at `/.well-known/jwks.json`
- CLI: `mcp-auth-middleware generate` — RSA-4096 JWKS key pair generation
- CLI: `mcp-auth-middleware k8s` — Kubernetes Secret YAML output
- CLI: `mcp-auth-middleware clean` — secure key deletion
