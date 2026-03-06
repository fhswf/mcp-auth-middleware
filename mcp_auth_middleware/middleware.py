"""JWE authentication middleware for Starlette/FastMCP."""
import logging
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .verifier import JWETokenVerifier

logger = logging.getLogger(__name__)

_user_context: ContextVar[dict] = ContextVar("user", default={})


@dataclass(frozen=True, slots=True)
class ScopeDefinition:
    """A JWT field that must be present for a request to be accepted."""

    scope: str
    description: str
    description_en: str

    def as_dict(self) -> dict[str, str]:
        return {
            "scope": self.scope,
            "description": self.description,
            "description_en": self.description_en,
        }


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
        app.add_middleware(JWKSAuthMiddleware, scopes=[...])
        uvicorn.run(app, host="0.0.0.0", port=8000)
    """

    def __init__(
        self,
        app,
        scopes: Sequence[ScopeDefinition | Mapping[str, str]] | None = None,
        verifier: JWETokenVerifier | None = None,
        jwks_path: str = "/.well-known/jwks.json",
        scopes_path: str = "/.well-known/fhswf-scopes",
    ):
        super().__init__(app)
        self.verifier = verifier or JWETokenVerifier()
        self.jwks_path = jwks_path
        self.scopes_path = scopes_path
        self.scopes = self._normalize_scopes(scopes)
        logger.info(
            "JWKSAuthMiddleware initialized (jwks_path=%s, scopes_path=%s, key_configured=%s, required_scopes=%d)",
            self.jwks_path,
            self.scopes_path,
            self.verifier.is_configured,
            len(self.scopes),
        )

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path == self.jwks_path:
            logger.debug("Serving JWKS endpoint: %s %s", request.method, request.url.path)
            return JSONResponse(self.verifier.get_jwks())
        if request.method == "GET" and request.url.path == self.scopes_path:
            logger.debug("Serving scopes endpoint: %s %s", request.method, request.url.path)
            return JSONResponse(
                {"scopes_supported": [scope.as_dict() for scope in self.scopes]},
                headers=self._cors_headers(),
            )

        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            if auth_header:
                logger.warning(
                    "Unsupported Authorization scheme: %s %s (expected 'Bearer')",
                    request.method,
                    request.url.path,
                )
            else:
                logger.warning(
                    "Missing Bearer token: %s %s",
                    request.method,
                    request.url.path,
                )
            return self._invalid_token_response()

        claims = await self.verifier.verify_token(auth_header[7:]) or {}
        if not claims:
            logger.warning(
                "Bearer token provided but verification failed: %s %s (client=%s)",
                request.method,
                request.url.path,
                request.client.host if request.client else "unknown",
            )
            return self._invalid_token_response()

        missing_scopes = [scope.as_dict() for scope in self.scopes if scope.scope not in claims]
        if missing_scopes:
            logger.warning(
                "Rejecting request with missing scopes: %s %s (missing=%s)",
                request.method,
                request.url.path,
                ",".join(item["scope"] for item in missing_scopes),
            )
            return JSONResponse(
                {"error": "missing_scopes", "missing": missing_scopes},
                status_code=403,
            )

        logger.debug(
            "Authenticated request: %s %s (user=%s)",
            request.method,
            request.url.path,
            claims.get("email") or claims.get("sub") or claims.get("name", "unknown"),
        )

        token = _user_context.set(claims)
        try:
            return await call_next(request)
        finally:
            _user_context.reset(token)

    @staticmethod
    def _normalize_scopes(
        scopes: Sequence[ScopeDefinition | Mapping[str, str]] | None,
    ) -> tuple[ScopeDefinition, ...]:
        if not scopes:
            raise ValueError("JWKSAuthMiddleware requires at least one configured scope.")

        normalized: list[ScopeDefinition] = []
        seen: set[str] = set()
        for raw_scope in scopes:
            if isinstance(raw_scope, ScopeDefinition):
                scope = raw_scope
            elif isinstance(raw_scope, Mapping):
                scope_name = raw_scope.get("scope")
                description = raw_scope.get("description")
                description_en = raw_scope.get("description_en")
                if not all(isinstance(value, str) for value in (scope_name, description, description_en)):
                    raise ValueError(
                        "Each configured scope must define string 'scope', 'description', and 'description_en' values."
                    )
                scope = ScopeDefinition(
                    scope=scope_name.strip(),
                    description=description.strip(),
                    description_en=description_en.strip(),
                )
            else:
                raise TypeError("Each configured scope must be a ScopeDefinition or mapping.")

            if not scope.scope or not scope.description or not scope.description_en:
                raise ValueError(
                    "Each configured scope must define non-empty 'scope', 'description', and 'description_en' values."
                )
            if scope.scope in seen:
                raise ValueError(f"Duplicate scope configured: {scope.scope}")

            seen.add(scope.scope)
            normalized.append(scope)

        return tuple(normalized)

    @staticmethod
    def _cors_headers() -> dict[str, str]:
        return {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET",
            "Access-Control-Allow-Headers": "*",
        }

    @staticmethod
    def _invalid_token_response() -> JSONResponse:
        return JSONResponse(
            {"error": "invalid_token"},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )
