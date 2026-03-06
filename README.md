# mcp-auth-middleware

JWE authentication middleware for HTTP MCP servers. Encrypt user data end-to-end so that only your MCP server can read it.

## What it does

`mcp-auth-middleware` gives your MCP server two things:

1. A middleware that decrypts a JWE Bearer token, validates `iat` and `exp`, enforces configured JWT scopes, and exposes the authenticated user's claims via `get_user()`.
2. A CLI (`mcp-auth-middleware`) that generates RSA key pairs in JWKS format, outputs Kubernetes Secret YAML, and securely deletes local keys when you're done.

The middleware also publishes:

- `/.well-known/jwks.json` for public key discovery
- `/.well-known/fhswf-scopes` for required scope discovery

## Installation

```bash
pip install mcp-auth-middleware
```

## Testing

```bash
python -m pip install -r requirements.txt
python -m pip install -e .
pytest --cov=mcp_auth_middleware --cov-report=term-missing --cov-fail-under=80
```

## Quick start

### 1. Generate keys

```bash
mcp-auth-middleware generate
```

This writes:

```text
.keys/mcp-private.json
.keys/mcp-public.json
```

### 2. Configure the private key

```bash
MCP_KEY_FILE_PATH=.keys/mcp-private.json
```

### 3. Add the middleware

```python
import uvicorn
from fastmcp import FastMCP

from mcp_auth_middleware import JWKSAuthMiddleware, get_user

mcp = FastMCP("My Server")

required_scopes = [
    {
        "scope": "name",
        "description": "Vor- und Nachname",
        "description_en": "First and last name",
    },
    {
        "scope": "email",
        "description": "E-Mail-Adresse",
        "description_en": "Email address",
    },
]


@mcp.tool()
def whoami() -> str:
    user = get_user()
    return f"Hello, {user.name}!"


app = mcp.http_app()
app.add_middleware(JWKSAuthMiddleware, scopes=required_scopes)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

### 4. Discover required scopes

`GET /.well-known/fhswf-scopes` returns exactly the scopes configured on that server:

```json
{
  "scopes_supported": [
    {
      "scope": "name",
      "description": "Vor- und Nachname",
      "description_en": "First and last name"
    },
    {
      "scope": "email",
      "description": "E-Mail-Adresse",
      "description_en": "Email address"
    }
  ]
}
```

The endpoint is public and includes permissive CORS headers.

### 5. Missing scope response

If a verified token is missing one or more configured fields, the middleware rejects the request with `403 Forbidden`:

```json
{
  "error": "missing_scopes",
  "missing": [
    {
      "scope": "email",
      "description": "E-Mail-Adresse",
      "description_en": "Email address"
    }
  ]
}
```

## API reference

### `JWKSAuthMiddleware`

Attach it to any Starlette-based MCP server app:

```python
app.add_middleware(
    JWKSAuthMiddleware,
    scopes=[
        {
            "scope": "name",
            "description": "Vor- und Nachname",
            "description_en": "First and last name",
        },
    ],
    verifier=None,
    jwks_path="/.well-known/jwks.json",
    scopes_path="/.well-known/fhswf-scopes",
)
```

Rules:

- `scopes` is required and must contain at least one scope.
- Every configured scope is mandatory.
- Scope names must match JWT field names.

### `get_user() -> AuthUser`

Returns the authenticated user's claims for the current request.

```python
user = get_user()
user.email
user["email"]
```

### `ScopeDefinition`

Optional helper dataclass for typed configuration:

```python
from mcp_auth_middleware import ScopeDefinition

scope = ScopeDefinition(
    scope="email",
    description="E-Mail-Adresse",
    description_en="Email address",
)
```

### `JWETokenVerifier`

Lower-level verifier if you need token verification outside the middleware:

```python
from mcp_auth_middleware import JWETokenVerifier

verifier = JWETokenVerifier()
claims = await verifier.verify_token(token_string)
public_jwks = verifier.get_jwks()
```

`verify_token()` returns `None` when token decryption fails or when `iat` / `exp` are invalid.

## Browser access

`/.well-known/fhswf-scopes` already includes CORS headers.

If browser clients also need `/.well-known/jwks.json`, add CORS middleware after `JWKSAuthMiddleware`:

```python
from starlette.middleware.cors import CORSMiddleware

app.add_middleware(JWKSAuthMiddleware, scopes=required_scopes)
app.add_middleware(CORSMiddleware, allow_origins=["*"])
```

## Kubernetes deployment

Generate a Secret manifest:

```bash
mcp-auth-middleware k8s | kubectl apply -f -
```

Clean up local key material:

```bash
mcp-auth-middleware clean
```

Mount the generated private key and set:

```bash
MCP_KEY_FILE_PATH=/etc/mcp/secrets/key.json
```

A full example Deployment + Service is in `examples/k8s-deployment.yaml`.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `MCP_KEY_FILE_PATH` | Yes | Path to the private JWKS JSON file |

## License

MIT
