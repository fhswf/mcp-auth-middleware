# mcp-auth-middleware

JWE authentication middleware for HTTP MCP servers. Encrypt user data end-to-end so that only your MCP server can read it.

## What it does

`mcp-auth-middleware` gives your MCP server two things:

1. **A middleware** that intercepts incoming requests, decrypts a JWE Bearer token, and makes the authenticated user's claims available via `get_user()`.
2. **A CLI** (`mcp-auth-middleware`) that generates RSA key pairs in JWKS format, outputs Kubernetes Secret YAML, and securely deletes local keys when you're done.

---

## Installation

```bash
pip install mcp-auth-middleware
```

This installs the library **and** the `mcp-auth-middleware` CLI.

---

## Quick start (local development)

### 1. Generate keys

```bash
mcp-auth-middleware generate
```

Output:

```
Keys generated (JWKS format):
  Private: .keys/mcp-private.json
  Public:  .keys/mcp-public.json
```

Add `.keys/` to your `.gitignore` immediately.

### 2. Set the environment variable

Create a `.env` file (or export directly):

```bash
MCP_KEY_FILE_PATH=.keys/mcp-private.json
```

### 3. Add the middleware to your MCP server

Works with any Starlette-based MCP server:

```python
from fastmcp import FastMCP
from mcp_auth_middleware import JWKSAuthMiddleware, get_user
import uvicorn

mcp = FastMCP("My Server")

# Register your tools on `mcp` as usual …

app = mcp.http_app()
app.add_middleware(JWKSAuthMiddleware)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

Or with the official MCP Python SDK directly:

```python
from mcp.server.fastmcp import FastMCP
from mcp_auth_middleware import JWKSAuthMiddleware, get_user
import uvicorn

mcp = FastMCP("My Server")

app = mcp.http_app()
app.add_middleware(JWKSAuthMiddleware)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

### 4. Access user claims inside any tool

```python
@mcp.tool()
def whoami() -> str:
    user = get_user()
    return f"Hello, {user.name or 'anonymous'}!"
```

`get_user()` returns an `AuthUser` dict. Access claims as attributes — missing keys return `None` instead of raising.

---

## Kubernetes deployment

### 1. Generate keys and pipe straight into kubectl

```bash
mcp-auth-middleware k8s | kubectl apply -f -
```

This creates a Kubernetes `Secret` named `mcp-server-keys` in the `default` namespace. Customise with flags:

```bash
mcp-auth-middleware k8s --namespace my-ns --secret-name my-mcp-keys | kubectl apply -f -
```

### 2. Clean up local key material

```bash
mcp-auth-middleware clean
```

Uses `shred` (Linux) for secure deletion when available; falls back to overwrite-then-delete.

### 3. Mount the secret in your deployment

Add the following snippets to your existing Deployment YAML.

**Volume definition** (under `spec.template.spec.volumes`):

```yaml
- name: mcp-secret-volume
  secret:
    secretName: mcp-server-keys   # must match --secret-name
    defaultMode: 0400
    items:
      - key: mcp_jwks
        path: key.json
```

**Volume mount** (under your container's `volumeMounts`):

```yaml
- mountPath: /etc/mcp/secrets
  name: mcp-secret-volume
  readOnly: true
```

**Environment variable** (under `env`):

```yaml
- name: MCP_KEY_FILE_PATH
  value: "/etc/mcp/secrets/key.json"
```

A full example Deployment + Service is in [`examples/k8s-deployment.yaml`](examples/k8s-deployment.yaml).

---

## CLI reference

All commands accept `-o / --output <dir>` to change the key directory (default: `.keys`).

| Command | Description |
|---|---|
| `mcp-auth-middleware generate` | Generate an RSA-4096 JWKS key pair |
| `mcp-auth-middleware k8s` | Generate keys and print a Kubernetes Secret YAML to stdout |
| `mcp-auth-middleware clean` | Securely delete keys from the output directory |

### `mcp-auth-middleware k8s` flags

| Flag | Default | Description |
|---|---|---|
| `-n, --namespace` | `default` | Kubernetes namespace |
| `-s, --secret-name` | `mcp-server-keys` | Name of the K8s Secret |

---

## API reference

### `JWKSAuthMiddleware`

Starlette middleware. Attach it to any HTTP-based MCP server app:

```python
app.add_middleware(
    JWKSAuthMiddleware,
    verifier=None,        # optional: provide your own JWETokenVerifier
    jwks_path="/.well-known/jwks.json",  # public-key endpoint path
)
```

The middleware automatically serves your server's **public** JWKS at the configured path so that token producers can discover your encryption key.

### `get_user() -> AuthUser`

Returns the authenticated user's claims for the current request. Safe to call from any async context (tools, routes, dependencies) during request handling.

```python
user = get_user()
user.email   # claim value or None
user["role"]  # also works as a regular dict
```

### `JWETokenVerifier`

Lower-level class if you need to verify tokens outside the middleware:

```python
from mcp_auth_middleware import JWETokenVerifier

verifier = JWETokenVerifier()          # reads MCP_KEY_FILE_PATH
claims = await verifier.verify_token(token_string)
public_jwks = verifier.get_jwks()       # for publishing
```

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `MCP_KEY_FILE_PATH` | Yes | Path to the private JWKS JSON file |

---

## How the token flow works

```
Producer (client/gateway)             MCP Server
――――――――――――――――――――――――――             ――――――――――
                                      GET /.well-known/jwks.json
                              ◄────   { public RSA key }
Encrypt claims with public key
POST /mcp/tool  ──────────────────────►
  Authorization: Bearer <JWE>
                                      Middleware decrypts JWE
                                      with private key
                                      ─► get_user() returns claims
```

1. The token producer fetches the server's public key from `/.well-known/jwks.json`.
2. It encrypts a JSON payload (user claims) into a JWE token using that public key.
3. The token is sent as a `Bearer` token in the `Authorization` header.
4. The middleware decrypts it with the private key and exposes claims via `get_user()`.

---

---

## Accessing the JWKS endpoint from a browser

If your token producer is a browser-based application that needs to fetch the public key from `/.well-known/jwks.json`, you must add CORS middleware **after** `JWKSAuthMiddleware`. Starlette applies middleware in reverse registration order, so the last one added runs first on incoming requests — this ensures CORS headers are set before auth is checked.
```python
from mcp_auth_middleware import JWKSAuthMiddleware
from starlette.middleware.cors import CORSMiddleware

app = mcp.http_app()
app.add_middleware(JWKSAuthMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restrict to your domain(s) in production 
)
```

Without this, browsers will block the cross-origin request to the JWKS endpoint due to the same-origin policy.

## Project structure

```
mcp-auth-middleware/
├── pyproject.toml
├── README.md
├── LICENSE
├── CHANGELOG.md
├── requirements.txt
├── requirements-dev.txt
├── MANIFEST.in
├── .gitignore
├── mcp_auth_middleware/
│   ├── __init__.py
│   ├── py.typed
│   ├── cli.py
│   ├── middleware.py
│   └── verifier.py
├── tests/
└── examples/
    ├── server.py
    └── k8s-deployment.yaml
```

---
## License

MIT
