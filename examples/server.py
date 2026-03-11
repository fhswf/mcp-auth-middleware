"""Minimal FastMCP server with mcp-auth-middleware authentication."""

import uvicorn
from dotenv import load_dotenv
from fastmcp import FastMCP

from mcp_auth_middleware import JWKSAuthMiddleware, get_user

load_dotenv()

mcp = FastMCP("Example MCP Server")

REQUIRED_SCOPES = [
    {"scope": "name"},
    {"scope": "email"},
]


@mcp.tool()
def whoami() -> str:
    """Return the authenticated user's identity."""
    user = get_user()
    return f"Authenticated as {user.name} (email: {user.email})"


@mcp.tool()
def greet(name: str) -> str:
    """Greet someone, mentioning who is asking."""
    user = get_user()
    return f"Hello {name}! (requested by {user.name})"


app = mcp.http_app()
app.add_middleware(JWKSAuthMiddleware, scopes=REQUIRED_SCOPES)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
