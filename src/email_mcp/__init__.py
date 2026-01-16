"""
Email MCP Server
================

Dumb pipe MCP server for AI agent email access via IMAP/POP3.

REQ-2026-002: Constitutional implementation following email_protocol_contract.
"""

__version__ = "0.1.0"

from src.email_mcp.credentials import Credentials, retrieve_credentials
from src.email_mcp.imap_client import EmailIMAPClient
from src.email_mcp.server import EmailMCPServer, create_server, get_server

__all__ = [
    "EmailMCPServer",
    "get_server",
    "create_server",
    "EmailIMAPClient",
    "Credentials",
    "retrieve_credentials",
]
