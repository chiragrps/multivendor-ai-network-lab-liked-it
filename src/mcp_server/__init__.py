"""Multivendor AI Network — MCP server package.

Exposes the tool's read + closed-loop surface to any MCP client
(Claude Code, Cursor, Cline, opencode, Claude Desktop).

Entry point: src/mcp_server/server.py::main
"""
from .server import main

__all__ = ["main"]
