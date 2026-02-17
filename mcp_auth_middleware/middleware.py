"""JWE authentication middleware for Starlette/FastMCP."""
import logging
from contextvars import ContextVar
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .verifier import JWETokenVerifier

logger = logging.getLogger(__name__)

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
        logger.info(
            "JWKSAuthMiddleware initialized (jwks_path=%s, key_configured=%s)",
            self.jwks_path,
            self.verifier.is_configured,
        )

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path == self.jwks_path:
            logger.debug("Serving JWKS endpoint: %s %s", request.method, request.url.path)
            return JSONResponse(self.verifier.get_jwks())

        auth_header = request.headers.get("authorization", "")
        claims = {}

        if auth_header.lower().startswith("bearer "):
            claims = await self.verifier.verify_token(auth_header[7:]) or {}
            if claims:
                logger.debug(
                    "Authenticated request: %s %s (user=%s)",
                    request.method,
                    request.url.path,
                    claims.get("email") or claims.get("sub") or claims.get("name", "unknown"),
                )
            else:
                logger.warning(
                    "Bearer token provided but verification failed: %s %s (client=%s)",
                    request.method,
                    request.url.path,
                    request.client.host if request.client else "unknown",
                )
        else:
            if auth_header:
                logger.warning(
                    "Unsupported Authorization scheme: %s %s (expected 'Bearer')",
                    request.method,
                    request.url.path,
                )
            else:
                logger.debug(
                    "Unauthenticated request: %s %s",
                    request.method,
                    request.url.path,
                )

        token = _user_context.set(claims)
        try:
            return await call_next(request)
        finally:
            _user_context.reset(token)