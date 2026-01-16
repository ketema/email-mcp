"""
Email MCP Server
================

MCP server implementing email access tools per contract specification.

CONSTITUTIONAL INVARIANTS ENFORCED:
- INV-GLOBAL-01: No delete methods exist
- INV-GLOBAL-02: No send/reply/forward methods exist
- INV-GLOBAL-03: No move methods exist
- INV-GLOBAL-05: No logging of message bodies or attachments
- INV-GLOBAL-06: Fetch does not mutate; mark-read is explicit
- INV-GLOBAL-08: Single connection per process
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from contracts import (
    ConnectionStatus,
    FolderNotFoundError,
    InvalidRangeError,
    NotConnectedError,
    UidNotFoundError,
)
from src.email_mcp.credentials import Credentials
from src.email_mcp.imap_client import EmailIMAPClient

# Configure logging to NEVER include message content (INV-GLOBAL-05)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("email-mcp")


class EmailMCPServer:
    """
    Email MCP Server - Read-only email access for AI agents.

    This class intentionally does NOT implement (adversarial test targets):
    - send, reply, forward, compose (INV-GLOBAL-02)
    - delete, remove, expunge (INV-GLOBAL-01)
    - move, copy, transfer (INV-GLOBAL-03)
    """

    def __init__(self) -> None:
        self._client: EmailIMAPClient | None = None
        self._server = Server("email-mcp")
        self._setup_tools()

    def _setup_tools(self) -> None:
        """Register MCP tools."""

        @self._server.list_tools()
        async def list_tools() -> list[Tool]:
            return [
                Tool(
                    name="email_fetch",
                    description="Fetch email messages from a folder with filtering options",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "folder": {
                                "type": "string",
                                "description": "Folder name (default: INBOX)",
                                "default": "INBOX",
                            },
                            "date_after": {
                                "type": "string",
                                "description": "ISO8601 datetime - only messages after this date",
                            },
                            "date_before": {
                                "type": "string",
                                "description": "ISO8601 datetime - only messages before this date",
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum messages to return (1-100)",
                                "minimum": 1,
                                "maximum": 100,
                            },
                            "uid_gt": {
                                "type": "integer",
                                "description": "Only messages with UID greater than this value",
                                "minimum": 0,
                            },
                        },
                        "required": ["limit"],
                    },
                ),
                Tool(
                    name="email_mark_read",
                    description="Mark messages as read (set \\Seen flag)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "folder": {
                                "type": "string",
                                "description": "Folder containing the messages",
                            },
                            "uids": {
                                "type": "array",
                                "items": {"type": "integer"},
                                "description": "List of message UIDs to mark as read",
                            },
                        },
                        "required": ["folder", "uids"],
                    },
                ),
                Tool(
                    name="email_list_folders",
                    description="List all available mailbox folders",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                    },
                ),
                Tool(
                    name="email_status",
                    description="Get current connection status",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                    },
                ),
            ]

        @self._server.call_tool()
        async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
            try:
                if name == "email_fetch":
                    result = self.email_fetch(**arguments)
                elif name == "email_mark_read":
                    result = self.email_mark_read(**arguments)
                elif name == "email_list_folders":
                    result = self.email_list_folders()
                elif name == "email_status":
                    result = self.email_status()
                else:
                    return [TextContent(type="text", text=f"Unknown tool: {name}")]

                return [TextContent(type="text", text=self._serialize_result(result))]

            except (
                NotConnectedError,
                InvalidRangeError,
                FolderNotFoundError,
                UidNotFoundError,
            ) as e:
                return [TextContent(type="text", text=f"Error: {e.__class__.__name__}: {e}")]

    def connect(self, credentials: Credentials) -> None:
        """
        Initialize connection with credentials.

        POST-STARTUP-02: Connection established
        POST-STARTUP-04: connection_status.connected == True
        INV-GLOBAL-08: Single connection per process
        """
        if self._client is not None:
            raise RuntimeError("Connection already established (INV-GLOBAL-08)")

        self._client = EmailIMAPClient()
        self._client.connect(credentials)
        logger.info("Connected to email server")  # No credentials logged (INV-GLOBAL-05)

    def disconnect(self) -> None:
        """Disconnect and clear client."""
        if self._client:
            self._client.disconnect()
            self._client = None
            logger.info("Disconnected from email server")

    def _require_client(self) -> EmailIMAPClient:
        """Ensure client is connected."""
        if self._client is None or not self._client.connected:
            raise NotConnectedError("Not connected to email server")
        return self._client

    def email_fetch(
        self,
        *,
        folder: str = "INBOX",
        date_after: str | None = None,
        date_before: str | None = None,
        limit: int,
        uid_gt: int | None = None,
    ) -> dict:
        """
        Fetch messages from folder.

        Implements EmailFetchContract.
        INV-FETCH-01: Does NOT mark messages as read.
        """
        client = self._require_client()
        # Log operation but NEVER log message content (INV-GLOBAL-05)
        logger.info(f"Fetching from {folder} with limit={limit}")
        return client.fetch_messages(
            folder=folder,
            date_after=date_after,
            date_before=date_before,
            limit=limit,
            uid_gt=uid_gt,
        )

    def email_mark_read(self, *, folder: str, uids: list[int]) -> dict:
        """
        Mark messages as read.

        Implements EmailMarkReadContract.
        INV-MARKREAD-01: Only \\Seen flag modified.
        """
        client = self._require_client()
        logger.info(f"Marking {len(uids)} messages as read in {folder}")
        return client.mark_read(folder=folder, uids=uids)

    def email_list_folders(self) -> dict:
        """
        List all folders.

        Implements EmailListFoldersContract.
        """
        client = self._require_client()
        logger.info("Listing folders")
        folders = client.list_folders()
        return {"folders": folders}

    def email_status(self) -> ConnectionStatus:
        """
        Get connection status.

        Implements EmailStatusContract.
        INV-STATUS-03: Always succeeds if callable.
        INV-STATUS-04: Honest about connection state.
        """
        if self._client is None:
            from contracts import EmailProtocol

            return ConnectionStatus(
                connected=False,
                protocol=EmailProtocol.IMAP,
                server="",
                uptime_seconds=0,
                tls_version="",
                cipher="",
            )
        return self._client.get_status()

    def _serialize_result(self, result: Any) -> str:
        """Serialize result to JSON string."""
        import json

        def default_serializer(obj: Any) -> Any:
            if hasattr(obj, "__dataclass_fields__"):
                return asdict(obj)
            if hasattr(obj, "value"):  # Enum
                return obj.value
            raise TypeError(f"Cannot serialize {type(obj)}")

        return json.dumps(result, default=default_serializer, indent=2)

    async def run(self) -> None:
        """Run the MCP server."""
        async with stdio_server() as (read_stream, write_stream):
            await self._server.run(
                read_stream, write_stream, self._server.create_initialization_options()
            )


# Singleton for process lifetime
_server_instance: EmailMCPServer | None = None


def get_server() -> EmailMCPServer:
    """Get or create the server singleton."""
    global _server_instance
    if _server_instance is None:
        _server_instance = EmailMCPServer()
    return _server_instance


def create_server() -> EmailMCPServer:
    """Create a new server instance (for testing)."""
    return EmailMCPServer()
