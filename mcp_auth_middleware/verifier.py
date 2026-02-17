"""JWE token verification and JWKS support."""
import json
import logging
import os
from typing import Any

from jose import jwe

logger = logging.getLogger(__name__)


class JWETokenVerifier:
    """Verifies JWE tokens and exposes public key as JWKS."""

    def __init__(self) -> None:
        self._jwk = self._load_key_from_env()
        if self._jwk:
            kid = self._jwk.get("kid", "unknown")
            kty = self._jwk.get("kty", "unknown")
            logger.info("JWE key loaded successfully (kid=%s, kty=%s)", kid, kty)
        else:
            logger.warning(
                "No JWE key configured — token verification is disabled. "
                "Set MCP_KEY_FILE_PATH to enable authentication."
            )

    @property
    def is_configured(self) -> bool:
        """Whether a decryption key is available."""
        return self._jwk is not None

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

    async def verify_token(self, token: str) -> dict[str, Any] | None:
        if not self._jwk:
            logger.debug("Skipping token verification — no key configured")
            return None

        try:
            decrypted = jwe.decrypt(token, self._jwk)
            payload = json.loads(decrypted)
            logger.debug("Token verified successfully")
            return payload.get("data", payload)
        except json.JSONDecodeError as e:
            logger.debug("Token decrypted but payload is not valid JSON: %s", e)
            return None
        except Exception as e:
            logger.debug("Token decryption detail: %s", e)
            return None

    def get_jwks(self) -> dict[str, Any]:
        if not self._jwk:
            logger.debug("JWKS requested but no key is configured — returning empty key set")
            return {"keys": []}

        public_fields = {"kty", "kid", "alg", "use", "n", "e"}
        public_jwk = {k: v for k, v in self._jwk.items() if k in public_fields}
        return {"keys": [public_jwk]}