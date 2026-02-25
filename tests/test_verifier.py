import asyncio
import json

import mcp_auth_middleware.verifier as verifier_module
from mcp_auth_middleware.verifier import JWETokenVerifier


def test_verifier_no_key_configured(monkeypatch) -> None:
    monkeypatch.delenv("MCP_KEY_FILE_PATH", raising=False)

    verifier = JWETokenVerifier()

    assert verifier.is_configured is False
    assert verifier.get_jwks() == {"keys": []}


def test_verifier_invalid_json(monkeypatch, tmp_path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{bad-json")
    monkeypatch.setenv("MCP_KEY_FILE_PATH", str(path))

    verifier = JWETokenVerifier()

    assert verifier.is_configured is False


def test_verifier_loads_first_jwks_key_and_filters_public_fields(monkeypatch, tmp_path) -> None:
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "kid1",
                "alg": "RSA-OAEP",
                "use": "enc",
                "n": "n",
                "e": "e",
                "d": "private",
            }
        ]
    }
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps(jwks))
    monkeypatch.setenv("MCP_KEY_FILE_PATH", str(path))

    verifier = JWETokenVerifier()

    assert verifier.is_configured is True
    assert verifier.get_jwks() == {
        "keys": [
            {
                "kty": "RSA",
                "kid": "kid1",
                "alg": "RSA-OAEP",
                "use": "enc",
                "n": "n",
                "e": "e",
            }
        ]
    }


def test_verify_token_returns_claims(monkeypatch, tmp_path) -> None:
    path = tmp_path / "key.json"
    path.write_text(json.dumps({"kty": "RSA", "kid": "kid1"}))
    monkeypatch.setenv("MCP_KEY_FILE_PATH", str(path))

    verifier = JWETokenVerifier()

    def fake_decrypt(token, jwk):
        return b'{"data": {"sub": "123"}}'

    monkeypatch.setattr(verifier_module.jwe, "decrypt", fake_decrypt)

    assert asyncio.run(verifier.verify_token("token")) == {"sub": "123"}


def test_verify_token_invalid_payload(monkeypatch, tmp_path) -> None:
    path = tmp_path / "key.json"
    path.write_text(json.dumps({"kty": "RSA", "kid": "kid1"}))
    monkeypatch.setenv("MCP_KEY_FILE_PATH", str(path))

    verifier = JWETokenVerifier()

    def fake_decrypt(token, jwk):
        return b"not json"

    monkeypatch.setattr(verifier_module.jwe, "decrypt", fake_decrypt)

    assert asyncio.run(verifier.verify_token("token")) is None


def test_verify_token_decrypt_exception(monkeypatch, tmp_path) -> None:
    path = tmp_path / "key.json"
    path.write_text(json.dumps({"kty": "RSA", "kid": "kid1"}))
    monkeypatch.setenv("MCP_KEY_FILE_PATH", str(path))

    verifier = JWETokenVerifier()

    def fake_decrypt(token, jwk):
        raise RuntimeError("boom")

    monkeypatch.setattr(verifier_module.jwe, "decrypt", fake_decrypt)

    assert asyncio.run(verifier.verify_token("token")) is None
