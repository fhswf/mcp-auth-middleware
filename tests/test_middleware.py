from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from mcp_auth_middleware.middleware import AuthUser, JWKSAuthMiddleware, get_user


class FakeVerifier:
    def __init__(self, claims: dict | None = None, jwks: dict | None = None) -> None:
        self._claims = claims
        self._jwks = jwks or {"keys": [{"kty": "RSA"}]}
        self.is_configured = True

    async def verify_token(self, token: str) -> dict | None:
        return self._claims

    def get_jwks(self) -> dict:
        return self._jwks


def build_app(verifier: FakeVerifier, jwks_path: str = "/.well-known/jwks.json") -> Starlette:
    async def me(request):
        return JSONResponse(dict(get_user()))

    routes = [Route("/me", me)]
    app = Starlette(routes=routes)
    app.add_middleware(JWKSAuthMiddleware, verifier=verifier, jwks_path=jwks_path)
    return app


def test_auth_user_attribute_access() -> None:
    user = AuthUser({"email": "dev@example.com"})
    assert user.email == "dev@example.com"
    assert user.missing is None


def test_middleware_serves_jwks() -> None:
    jwks = {"keys": [{"kty": "RSA", "kid": "kid1"}]}
    app = build_app(FakeVerifier(jwks=jwks))

    client = TestClient(app)
    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    assert response.json() == jwks


def test_middleware_sets_user_from_bearer_token() -> None:
    claims = {"sub": "123", "email": "dev@example.com"}
    app = build_app(FakeVerifier(claims=claims))

    client = TestClient(app)
    response = client.get("/me", headers={"Authorization": "Bearer token"})

    assert response.status_code == 200
    assert response.json() == claims
    assert dict(get_user()) == {}


def test_middleware_ignores_non_bearer_auth() -> None:
    app = build_app(FakeVerifier(claims={"sub": "123"}))

    client = TestClient(app)
    response = client.get("/me", headers={"Authorization": "Basic abc"})

    assert response.status_code == 200
    assert response.json() == {}


def test_middleware_handles_failed_verification() -> None:
    app = build_app(FakeVerifier(claims=None))

    client = TestClient(app)
    response = client.get("/me", headers={"Authorization": "Bearer bad"})

    assert response.status_code == 200
    assert response.json() == {}
