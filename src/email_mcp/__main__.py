"""
Email MCP Server Entry Point
============================

Enables execution via: python -m email_mcp

PRE: biosecret must be accessible (biometric auth available)
PRE: IMAP credentials must exist in keychain
POST: MCP server running on stdio, ready for tool calls
INV: No credentials stored outside process memory
"""

import asyncio
import sys

from src.email_mcp.server import EmailMCPServer


def main() -> int:
    """
    Entry point for Email MCP Server.

    PRE: None (credentials loaded on startup)
    POST: Server terminated with exit code
    ERRORS: Non-zero exit on startup failure
    """
    server = EmailMCPServer()
    try:
        asyncio.run(server.run())
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
