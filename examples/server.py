"""Minimal FastMCP server with mcp-auth-middleware authentication."""

from fastmcp import FastMCP
from dotenv import load_dotenv

load_dotenv()

from fastmcp_auth import JWKSAuthMiddleware, get_user
import uvicorn

mcp = FastMCP("Example MCP Server")


@mcp.tool()
def whoami() -> str:
    """Return the authenticated user's identity."""
    user = get_user()
    if user.sub:
        return f"Authenticated as {user.sub} (email: {user.email})"
    return "No authentication token provided."


@mcp.tool()
def greet(name: str) -> str:
    """Greet someone, mentioning who is asking."""
    user = get_user()
    caller = user.name or "anonymous"
    return f"Hello {name}! (requested by {caller})"


app = mcp.http_app()
app.add_middleware(JWKSAuthMiddleware)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
