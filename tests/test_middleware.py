from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from mcp_auth_middleware.middleware import AuthUser, JWKSAuthMiddleware, ScopeDefinition, get_user

SCOPES = [
    {"scope": "name"},
    {"scope": "email"},
]


class FakeVerifier:
    def __init__(self, claims: dict | None = None, jwks: dict | None = None) -> None:
        self._claims = claims
        self._jwks = jwks or {"keys": [{"kty": "RSA"}]}
        self.is_configured = True

    async def verify_token(self, token: str) -> dict | None:
        return self._claims

    def get_jwks(self) -> dict:
        return self._jwks


def build_app(
    verifier: FakeVerifier,
    scopes: list[dict[str, str]] | None = None,
    jwks_path: str = "/.well-known/jwks.json",
    scopes_path: str = "/.well-known/fhswf-scopes",
) -> Starlette:
    async def me(request):
        return JSONResponse(dict(get_user()))

    routes = [Route("/me", me)]
    app = Starlette(routes=routes)
    app.add_middleware(
        JWKSAuthMiddleware,
        verifier=verifier,
        scopes=scopes or SCOPES,
        jwks_path=jwks_path,
        scopes_path=scopes_path,
    )
    return app


def test_auth_user_attribute_access() -> None:
    user = AuthUser({"email": "dev@example.com"})
    assert user.email == "dev@example.com"
    assert user.missing is None


def test_middleware_requires_at_least_one_scope() -> None:
    try:
        JWKSAuthMiddleware(Starlette(), verifier=FakeVerifier(), scopes=[])
    except ValueError as exc:
        assert "at least one configured scope" in str(exc)
    else:
        raise AssertionError("Expected ValueError for empty scopes")


def test_middleware_rejects_duplicate_scopes() -> None:
    try:
        JWKSAuthMiddleware(
            Starlette(),
            verifier=FakeVerifier(),
            scopes=[
                {
                    "scope": "email",
                    "description": "E-Mail-Adresse",
                    "description_en": "Email address",
                },
                ScopeDefinition(scope="email"),
            ],
        )
    except ValueError as exc:
        assert "Duplicate scope configured: email" == str(exc)
    else:
        raise AssertionError("Expected ValueError for duplicate scopes")


def test_middleware_serves_jwks() -> None:
    jwks = {"keys": [{"kty": "RSA", "kid": "kid1"}]}
    app = build_app(FakeVerifier(jwks=jwks))

    client = TestClient(app)
    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    assert response.json() == jwks


def test_middleware_serves_scopes_with_cors_headers() -> None:
    app = build_app(FakeVerifier())

    client = TestClient(app)
    response = client.get("/.well-known/fhswf-scopes")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["access-control-allow-origin"] == "*"
    assert response.headers["access-control-allow-methods"] == "GET"
    assert response.json() == {"scopes_supported": SCOPES}


def test_middleware_sets_user_from_bearer_token() -> None:
    claims = {"sub": "123", "name": "Dev", "email": "dev@example.com"}
    app = build_app(FakeVerifier(claims=claims))

    client = TestClient(app)
    response = client.get("/me", headers={"Authorization": "Bearer token"})

    assert response.status_code == 200
    assert response.json() == claims
    assert dict(get_user()) == {}


def test_middleware_rejects_missing_bearer_token() -> None:
    app = build_app(FakeVerifier(claims={"name": "Dev", "email": "dev@example.com"}))

    client = TestClient(app)
    response = client.get("/me")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json() == {"error": "invalid_token"}


def test_middleware_rejects_non_bearer_auth() -> None:
    app = build_app(FakeVerifier(claims={"name": "Dev", "email": "dev@example.com"}))

    client = TestClient(app)
    response = client.get("/me", headers={"Authorization": "Basic abc"})

    assert response.status_code == 401
    assert response.json() == {"error": "invalid_token"}


def test_middleware_handles_failed_verification() -> None:
    app = build_app(FakeVerifier(claims=None))

    client = TestClient(app)
    response = client.get("/me", headers={"Authorization": "Bearer bad"})

    assert response.status_code == 401
    assert response.json() == {"error": "invalid_token"}


def test_middleware_serves_scope_only_even_with_legacy_scope_config() -> None:
    app = build_app(
        FakeVerifier(),
        scopes=[
            {
                "scope": "email",
                "description": "E-Mail-Adresse",
                "description_en": "Email address",
            }
        ],
    )

    client = TestClient(app)
    response = client.get("/.well-known/fhswf-scopes")

    assert response.status_code == 200
    assert response.json() == {"scopes_supported": [{"scope": "email"}]}


def test_middleware_rejects_missing_scopes_with_scope_only_payload() -> None:
    app = build_app(FakeVerifier(claims={"name": "Dev"}))

    client = TestClient(app)
    response = client.get("/me", headers={"Authorization": "Bearer token"})

    assert response.status_code == 403
    assert response.json() == {
        "error": "missing_scopes",
        "missing": [{"scope": "email"}],
    }
