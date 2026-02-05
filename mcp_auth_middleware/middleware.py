"""JWE authentication middleware for Starlette/FastMCP."""

from contextvars import ContextVar
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .verifier import JWETokenVerifier

_user_context: ContextVar[dict] = ContextVar("user", default={})


class AuthUser(dict):
    """User claims with attribute access. Missing keys return None."""

    def __getattr__(self, name: str) -> Any:
        return self.get(name)


def get_user() -> AuthUser:
    """Get authenticated user from current request context."""
    return AuthUser(_user_context.get())


class JWKSAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware that decrypts JWE Bearer tokens and serves JWKS endpoint.

    Usage:
        app = mcp.http_app()
        app.add_middleware(JWKSAuthMiddleware)
        uvicorn.run(app, host="0.0.0.0", port=8000)
    """

    def __init__(
        self,
        app,
        verifier: JWETokenVerifier | None = None,
        jwks_path: str = "/.well-known/jwks.json",
    ):
        super().__init__(app)
        self.verifier = verifier or JWETokenVerifier()
        self.jwks_path = jwks_path

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path == self.jwks_path:
            return JSONResponse(self.verifier.get_jwks())

        claims = {}
        if (auth := request.headers.get("authorization", "")).lower().startswith(
            "bearer "
        ):
            claims = await self.verifier.verify_token(auth[7:]) or {}

        token = _user_context.set(claims)
        try:
            return await call_next(request)
        finally:
            _user_context.reset(token)
