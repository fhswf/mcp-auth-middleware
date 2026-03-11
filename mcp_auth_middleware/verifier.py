"""JWE token verification and JWKS support."""
import json
import logging
import os
import time
from typing import Any

from joserfc import jwe, jwk

logger = logging.getLogger(__name__)


class JWETokenVerifier:
    """Verifies JWE tokens and exposes public key as JWKS."""

    def __init__(self) -> None:
        self._jwk = self._load_key_from_env()
        self._key = self._import_key(self._jwk) if self._jwk else None
        if self._jwk and self._key:
            kid = self._jwk.get("kid", "unknown")
            kty = self._jwk.get("kty", "unknown")
            logger.info("JWE key loaded successfully (kid=%s, kty=%s)", kid, kty)
        else:
            logger.warning(
                "No JWE key configured - token verification is disabled. "
                "Set MCP_KEY_FILE_PATH to enable authentication."
            )

    @property
    def is_configured(self) -> bool:
        """Whether a decryption key is available."""
        return self._key is not None

    @staticmethod
    def _load_key_from_env() -> dict | None:
        path = os.environ.get("MCP_KEY_FILE_PATH")
        if not path:
            logger.debug("MCP_KEY_FILE_PATH not set")
            return None

        logger.debug("Loading key from %s", path)
        try:
            with open(path) as f:
                data = json.load(f)
        except FileNotFoundError:
            logger.error("Key file not found: %s", path)
            return None
        except json.JSONDecodeError as e:
            logger.error("Key file is not valid JSON (%s): %s", path, e)
            return None

        if "keys" in data and isinstance(data["keys"], list):
            if not data["keys"]:
                logger.error("JWKS file contains empty 'keys' array: %s", path)
                return None
            logger.debug("Loaded first key from JWKS key set (%d keys total)", len(data["keys"]))
            return data["keys"][0]

        return data

    @staticmethod
    def _import_key(raw_jwk: dict[str, Any] | None) -> Any | None:
        if raw_jwk is None:
            return None

        try:
            return jwk.import_key(raw_jwk)
        except Exception as e:
            logger.error("Failed to import JWK: %s", e)
            return None

    async def verify_token(self, token: str) -> dict[str, Any] | None:
        if not self._key:
            logger.debug("Skipping token verification - no key configured")
            return None

        try:
            decrypted = jwe.decrypt_compact(token, self._key, algorithms=["RSA-OAEP"])
            payload = json.loads(decrypted.plaintext)
            if not isinstance(payload, dict):
                logger.debug("Token payload is not a JSON object")
                return None
            if not self._timestamps_are_valid(payload):
                return None
            claims = payload.get("data", payload)
            if not isinstance(claims, dict):
                logger.debug("Token payload is not a JSON object")
                return None
            logger.debug("Token verified successfully")
            return claims
        except json.JSONDecodeError as e:
            logger.debug("Token decrypted but payload is not valid JSON: %s", e)
            return None
        except Exception as e:
            logger.debug("Token decryption detail: %s", e)
            return None

    @staticmethod
    def _timestamps_are_valid(payload: dict[str, Any]) -> bool:
        iat = payload.get("iat")
        exp = payload.get("exp")
        if not JWETokenVerifier._is_numeric_date(iat) or not JWETokenVerifier._is_numeric_date(exp):
            logger.debug("Token missing numeric iat/exp claims")
            return False

        now = time.time()
        if iat > now:
            logger.debug("Token iat is in the future")
            return False
        if exp <= iat:
            logger.debug("Token exp must be after iat")
            return False
        if exp <= now:
            logger.debug("Token has expired")
            return False

        return True

    @staticmethod
    def _is_numeric_date(value: Any) -> bool:
        return isinstance(value, int | float) and not isinstance(value, bool)

    def get_jwks(self) -> dict[str, Any]:
        if not self._jwk:
            logger.debug("JWKS requested but no key is configured - returning empty key set")
            return {"keys": []}

        public_fields = {"kty", "kid", "alg", "use", "n", "e"}
        public_jwk = {k: v for k, v in self._jwk.items() if k in public_fields}
        return {"keys": [public_jwk]}
