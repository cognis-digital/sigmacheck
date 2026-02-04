"""SIGMACHECK MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from sigmacheck.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-sigmacheck[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-sigmacheck[mcp]'")
        return 1
    app = FastMCP("sigmacheck")

    @app.tool()
    def sigmacheck_scan(target: str) -> str:
        """Lint and unit-test Sigma detection rules against sample events. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
