import asyncio
import json
import uuid
from pathlib import Path

import mcp_auth_middleware.verifier as verifier_module
from mcp_auth_middleware.verifier import JWETokenVerifier


def write_key_file(contents: dict | str) -> str:
    temp_dir = Path(__file__).resolve().parent.parent / ".test-tmp" / str(uuid.uuid4())
    temp_dir.mkdir(parents=True, exist_ok=True)
    path = Path(temp_dir) / "key.json"
    if isinstance(contents, str):
        path.write_text(contents)
    else:
        path.write_text(json.dumps(contents))
    return str(path)


def test_verifier_no_key_configured(monkeypatch) -> None:
    monkeypatch.delenv("MCP_KEY_FILE_PATH", raising=False)

    verifier = JWETokenVerifier()

    assert verifier.is_configured is False
    assert verifier.get_jwks() == {"keys": []}


def test_verifier_invalid_json(monkeypatch) -> None:
    monkeypatch.setenv("MCP_KEY_FILE_PATH", write_key_file("{bad-json"))

    verifier = JWETokenVerifier()

    assert verifier.is_configured is False


def test_verifier_loads_first_jwks_key_and_filters_public_fields(monkeypatch) -> None:
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
    monkeypatch.setenv("MCP_KEY_FILE_PATH", write_key_file(jwks))

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


def test_verify_token_returns_claims(monkeypatch) -> None:
    monkeypatch.setenv("MCP_KEY_FILE_PATH", write_key_file({"kty": "RSA", "kid": "kid1"}))

    verifier = JWETokenVerifier()

    def fake_decrypt(token, jwk):
        return b'{"data": {"sub": "123", "iat": 900, "exp": 1100}}'

    monkeypatch.setattr(verifier_module.jwe, "decrypt", fake_decrypt)

    assert asyncio.run(verifier.verify_token("token")) == {"sub": "123", "iat": 900, "exp": 1100}


def test_verify_token_accepts_missing_timestamps(monkeypatch) -> None:
    monkeypatch.setenv("MCP_KEY_FILE_PATH", write_key_file({"kty": "RSA", "kid": "kid1"}))

    verifier = JWETokenVerifier()

    def fake_decrypt(token, jwk):
        return b'{"data": {"sub": "123"}}'

    monkeypatch.setattr(verifier_module.jwe, "decrypt", fake_decrypt)

    assert asyncio.run(verifier.verify_token("token")) == {"sub": "123"}


def test_verify_token_accepts_future_iat(monkeypatch) -> None:
    monkeypatch.setenv("MCP_KEY_FILE_PATH", write_key_file({"kty": "RSA", "kid": "kid1"}))

    verifier = JWETokenVerifier()

    def fake_decrypt(token, jwk):
        return b'{"data": {"sub": "123", "iat": 1001, "exp": 1100}}'

    monkeypatch.setattr(verifier_module.jwe, "decrypt", fake_decrypt)

    assert asyncio.run(verifier.verify_token("token")) == {"sub": "123", "iat": 1001, "exp": 1100}


def test_verify_token_accepts_expired_token(monkeypatch) -> None:
    monkeypatch.setenv("MCP_KEY_FILE_PATH", write_key_file({"kty": "RSA", "kid": "kid1"}))

    verifier = JWETokenVerifier()

    def fake_decrypt(token, jwk):
        return b'{"data": {"sub": "123", "iat": 900, "exp": 999}}'

    monkeypatch.setattr(verifier_module.jwe, "decrypt", fake_decrypt)

    assert asyncio.run(verifier.verify_token("token")) == {"sub": "123", "iat": 900, "exp": 999}


def test_verify_token_invalid_payload(monkeypatch) -> None:
    monkeypatch.setenv("MCP_KEY_FILE_PATH", write_key_file({"kty": "RSA", "kid": "kid1"}))

    verifier = JWETokenVerifier()

    def fake_decrypt(token, jwk):
        return b"not json"

    monkeypatch.setattr(verifier_module.jwe, "decrypt", fake_decrypt)

    assert asyncio.run(verifier.verify_token("token")) is None


def test_verify_token_decrypt_exception(monkeypatch) -> None:
    monkeypatch.setenv("MCP_KEY_FILE_PATH", write_key_file({"kty": "RSA", "kid": "kid1"}))

    verifier = JWETokenVerifier()

    def fake_decrypt(token, jwk):
        raise RuntimeError("boom")

    monkeypatch.setattr(verifier_module.jwe, "decrypt", fake_decrypt)

    assert asyncio.run(verifier.verify_token("token")) is None
