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

    @staticmethod
    def _load_key_from_env() -> dict | None:
        path = os.environ.get("MCP_KEY_FILE_PATH")
        if not path:
            return None

        try:
            with open(path) as f:
                data = json.load(f)

            if "keys" in data and isinstance(data["keys"], list):
                return data["keys"][0]
            return data

        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Key loading error: {e}")
            return None

    async def verify_token(self, token: str) -> dict[str, Any] | None:
        if not self._jwk:
            return None
        try:
            payload = json.loads(jwe.decrypt(token, self._jwk))
            return payload.get("data", payload)
        except Exception as e:
            logger.debug(f"Token verification failed: {e}")
            return None

    def get_jwks(self) -> dict[str, Any]:
        if not self._jwk:
            return {"keys": []}
        public_fields = {"kty", "kid", "alg", "use", "n", "e"}
        public_jwk = {k: v for k, v in self._jwk.items() if k in public_fields}
        return {"keys": [public_jwk]}
