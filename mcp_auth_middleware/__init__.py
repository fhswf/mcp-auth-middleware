"""MCP Secrets - JWE authentication middleware for FastMCP/Starlette."""

from .middleware import AuthUser, JWKSAuthMiddleware, ScopeDefinition, get_user
from .verifier import JWETokenVerifier

__version__ = "0.1.0"
__all__ = ["JWETokenVerifier", "JWKSAuthMiddleware", "ScopeDefinition", "get_user", "AuthUser"]
