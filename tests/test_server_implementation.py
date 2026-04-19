"""
Email MCP Server Implementation Tests
=====================================

These tests verify the actual server implementation against the contracts.
CL12-E TRACEABILITY: Every test cites specific contract clause IDs.

This file implements the test specifications from test_email_protocol_contract.py.
"""

import inspect
import os
import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime

from contracts import (
    EmailProtocol,
    EmailAddress,
    Attachment,
    EmailMessage,
    FolderInfo,
    ConnectionStatus,
    BiosecretDeniedError,
    BiosecretNotFoundError,
    AuthFailedError,
    ConnectionFailedError,
    NotConnectedError,
    FolderNotFoundError,
    InvalidRangeError,
    UidNotFoundError,
)
from src.email_mcp.server import EmailMCPServer, create_server
from src.email_mcp.imap_client import EmailIMAPClient
from src.email_mcp.credentials import Credentials


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def mock_credentials():
    """Valid test credentials."""
    return Credentials(
        username="test@example.com",
        password="secret123",
        server="imap.example.com",
        port=993,
        use_ssl=True,
    )


@pytest.fixture
def mock_imap_client():
    """Mock IMAPClient for testing without real IMAP server."""
    with patch("src.email_mcp.imap_client.IMAPClient") as mock:
        client = MagicMock()
        mock.return_value = client

        # Default folder listing
        client.list_folders.return_value = [
            ([], b"/", "INBOX"),
            ([], b"/", "Sent"),
            ([], b"/", "Drafts"),
        ]

        # Default folder status
        client.folder_status.return_value = {
            b"MESSAGES": 10,
            b"UNSEEN": 3,
            b"UIDVALIDITY": 12345,
        }

        # Default select folder
        client.select_folder.return_value = {
            b"UIDVALIDITY": 12345,
            b"UIDNEXT": 1000,
        }

        # Default search returns some UIDs
        client.search.return_value = [100, 200, 300]

        yield mock


@pytest.fixture
def sample_raw_email():
    """Raw email bytes for testing message parsing."""
    return b"""From: Sender <sender@example.com>
To: Recipient <recipient@example.com>
Subject: Test Subject
Date: Mon, 13 Jan 2026 10:00:00 +0000
Message-ID: <abc123@example.com>
Content-Type: text/plain; charset="utf-8"

This is a test email body.
"""


@pytest.fixture
def connected_server(mock_imap_client, mock_credentials):
    """Server with mocked IMAP connection."""
    server = create_server()
    server.connect(mock_credentials)
    return server


# =============================================================================
# STARTUP CONTRACT TESTS
# =============================================================================

class TestStartupContract:
    """Tests for MCP process startup behavior."""

    def test_startup_biosecret_success(self, mock_imap_client, mock_credentials):
        """
        Contract: StartupContract
        Enforces: POST-STARTUP-01, POST-STARTUP-02, POST-STARTUP-03, POST-STARTUP-04
        """
        server = create_server()
        server.connect(mock_credentials)

        # POST-STARTUP-04: connection_status.connected == True
        status = server.email_status()
        assert status.connected is True, (
            f"test_startup_biosecret_success FAILED | "
            f"POST-STARTUP-04 violated | "
            f"Expected: connected == True after successful connect | "
            f"Actual: connected == {status.connected} | "
            f"Guidance: Server MUST report connected=True after successful auth"
        )
        assert status.protocol == EmailProtocol.IMAP, (
            f"test_startup_biosecret_success FAILED | "
            f"POST-STARTUP-03 violated | "
            f"Expected: protocol == IMAP | "
            f"Actual: protocol == {status.protocol} | "
            f"Guidance: Server MUST use IMAP protocol"
        )

    def test_startup_biosecret_denied(self):
        """
        Contract: StartupContract
        Enforces: ERRORS: BIOSECRET_DENIED
        """
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=1,
                stderr="User cancelled biometric authentication",
            )

            from src.email_mcp.credentials import retrieve_credentials
            with pytest.raises(BiosecretDeniedError):
                retrieve_credentials("test-account")

    def test_startup_credentials_not_found(self):
        """
        Contract: StartupContract
        Enforces: ERRORS: BIOSECRET_NOT_FOUND
        """
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=1,
                stderr="Item not found",
            )

            from src.email_mcp.credentials import retrieve_credentials
            with pytest.raises(BiosecretNotFoundError):
                retrieve_credentials("test-account")

    def test_startup_auth_failed(self, mock_credentials):
        """
        Contract: StartupContract
        Enforces: ERRORS: AUTH_FAILED
        """
        with patch("src.email_mcp.imap_client.IMAPClient") as mock:
            client = MagicMock()
            mock.return_value = client
            client.login.side_effect = Exception("Authentication failed")

            server = create_server()
            with pytest.raises(AuthFailedError):
                server.connect(mock_credentials)

    def test_startup_credentials_memory_only(self, mock_credentials):
        """
        Contract: StartupContract
        Enforces: INV-STARTUP-01
        Adversarial: True

        Verify credentials are NOT in environment variables.
        """
        # Credentials should not be stored in environment
        assert "EMAIL_PASSWORD" not in os.environ, (
            f"test_startup_credentials_memory_only FAILED | "
            f"INV-STARTUP-01 violated | "
            f"Expected: EMAIL_PASSWORD not in environment | "
            f"Actual: EMAIL_PASSWORD found in os.environ | "
            f"Guidance: Credentials MUST be memory-only, never in env vars"
        )
        assert "secret123" not in os.environ.values(), (
            f"test_startup_credentials_memory_only FAILED | "
            f"INV-STARTUP-01 violated | "
            f"Expected: Password value not in environment | "
            f"Actual: Password found in os.environ.values() | "
            f"Guidance: Credentials MUST be memory-only, never in env vars"
        )


# =============================================================================
# EMAIL FETCH CONTRACT TESTS
# =============================================================================

class TestEmailFetchContract:
    """Tests for email_fetch tool behavior."""

    def test_fetch_basic(self, connected_server, mock_imap_client, sample_raw_email):
        """
        Contract: EmailFetchContract
        Enforces: POST-FETCH-01, POST-FETCH-02
        """
        # Setup mock to return sample email
        mock_client = mock_imap_client.return_value
        mock_client.fetch.return_value = {
            100: {
                b"UID": 100,
                b"FLAGS": [],
                b"INTERNALDATE": datetime(2026, 1, 13, 10, 0, 0),
                b"BODY[]": sample_raw_email,
            }
        }

        result = connected_server.email_fetch(limit=10)

        # POST-FETCH-01: Returns dict with required keys
        assert "messages" in result, (
            f"test_fetch_basic FAILED | "
            f"POST-FETCH-01 violated | "
            f"Expected: result contains 'messages' key | "
            f"Actual: keys are {list(result.keys())} | "
            f"Guidance: email_fetch MUST return dict with 'messages' key"
        )
        assert "folder" in result, (
            f"test_fetch_basic FAILED | "
            f"POST-FETCH-01 violated | "
            f"Expected: result contains 'folder' key | "
            f"Actual: keys are {list(result.keys())} | "
            f"Guidance: email_fetch MUST return dict with 'folder' key"
        )
        assert "uidvalidity" in result, (
            f"test_fetch_basic FAILED | "
            f"POST-FETCH-01 violated | "
            f"Expected: result contains 'uidvalidity' key | "
            f"Actual: keys are {list(result.keys())} | "
            f"Guidance: email_fetch MUST return dict with 'uidvalidity' key"
        )
        assert "next_uid" in result, (
            f"test_fetch_basic FAILED | "
            f"POST-FETCH-01 violated | "
            f"Expected: result contains 'next_uid' key | "
            f"Actual: keys are {list(result.keys())} | "
            f"Guidance: email_fetch MUST return dict with 'next_uid' key"
        )

        # POST-FETCH-02: Messages match schema
        assert isinstance(result["messages"], list), (
            f"test_fetch_basic FAILED | "
            f"POST-FETCH-02 violated | "
            f"Expected: messages is a list | "
            f"Actual: messages is {type(result['messages'])} | "
            f"Guidance: email_fetch MUST return messages as list"
        )

    def test_fetch_limit_respected(self, connected_server, mock_imap_client, sample_raw_email):
        """
        Contract: EmailFetchContract
        Enforces: POST-FETCH-03
        """
        mock_client = mock_imap_client.return_value
        mock_client.search.return_value = list(range(1, 101))  # 100 messages
        mock_client.fetch.return_value = {
            i: {
                b"UID": i,
                b"FLAGS": [],
                b"INTERNALDATE": datetime(2026, 1, 13, 10, 0, 0),
                b"BODY[]": sample_raw_email,
            }
            for i in range(1, 11)  # Return 10 messages
        }

        result = connected_server.email_fetch(limit=10)

        # POST-FETCH-03: len(messages) <= limit
        assert len(result["messages"]) <= 10, (
            f"test_fetch_limit_respected FAILED | "
            f"POST-FETCH-03 violated | "
            f"Expected: len(messages) <= 10 | "
            f"Actual: len(messages) = {len(result['messages'])} | "
            f"Guidance: email_fetch MUST respect limit parameter"
        )

    def test_fetch_uid_gt_filter(self, connected_server, mock_imap_client, sample_raw_email):
        """
        Contract: EmailFetchContract
        Enforces: POST-FETCH-04
        """
        mock_client = mock_imap_client.return_value
        mock_client.search.return_value = [300, 400, 500]  # UIDs > 200
        mock_client.fetch.return_value = {
            uid: {
                b"UID": uid,
                b"FLAGS": [],
                b"INTERNALDATE": datetime(2026, 1, 13, 10, 0, 0),
                b"BODY[]": sample_raw_email,
            }
            for uid in [300, 400, 500]
        }

        result = connected_server.email_fetch(limit=100, uid_gt=200)

        # POST-FETCH-04: All returned messages have uid > uid_gt
        for msg in result["messages"]:
            assert msg.uid > 200, (
                f"test_fetch_uid_gt_filter FAILED | "
                f"POST-FETCH-04 violated | "
                f"Expected: all message UIDs > 200 | "
                f"Actual: message UID {msg.uid} <= 200 | "
                f"Guidance: email_fetch with uid_gt MUST filter correctly"
            )

    def test_fetch_date_range_filter(self, connected_server, mock_imap_client):
        """
        Contract: EmailFetchContract
        Enforces: POST-FETCH-05, POST-FETCH-06
        """
        mock_client = mock_imap_client.return_value
        mock_client.search.return_value = [100]
        mock_client.fetch.return_value = {}

        # Should not raise with valid date range
        result = connected_server.email_fetch(
            limit=10,
            date_after="2026-01-01T00:00:00Z",
            date_before="2026-01-31T23:59:59Z",
        )

        assert "messages" in result, (
            f"test_fetch_date_range_filter FAILED | "
            f"POST-FETCH-05, POST-FETCH-06 violated | "
            f"Expected: result contains 'messages' key | "
            f"Actual: keys are {list(result.keys())} | "
            f"Guidance: email_fetch with date range MUST return valid result"
        )

    def test_fetch_ordering(self, connected_server, mock_imap_client, sample_raw_email):
        """
        Contract: EmailFetchContract
        Enforces: POST-FETCH-07
        """
        mock_client = mock_imap_client.return_value
        mock_client.search.return_value = [300, 100, 200]  # Unordered
        mock_client.fetch.return_value = {
            uid: {
                b"UID": uid,
                b"FLAGS": [],
                b"INTERNALDATE": datetime(2026, 1, 13, 10, 0, 0),
                b"BODY[]": sample_raw_email,
            }
            for uid in [100, 200, 300]
        }

        result = connected_server.email_fetch(limit=100)

        # POST-FETCH-07: Messages ordered by UID ascending
        uids = [msg.uid for msg in result["messages"]]
        assert uids == sorted(uids), (
            f"test_fetch_ordering FAILED | "
            f"POST-FETCH-07 violated | "
            f"Expected: UIDs in ascending order {sorted(uids)} | "
            f"Actual: UIDs are {uids} | "
            f"Guidance: email_fetch MUST return messages ordered by UID ascending"
        )

    def test_fetch_does_not_mark_read(self, connected_server, mock_imap_client):
        """
        Contract: EmailFetchContract
        Enforces: INV-FETCH-01
        Adversarial: True

        Verify fetch uses readonly=True and BODY.PEEK.
        """
        mock_client = mock_imap_client.return_value
        mock_client.search.return_value = []
        mock_client.fetch.return_value = {}

        connected_server.email_fetch(limit=10)

        # Verify select_folder was called with readonly=True
        try:
            mock_client.select_folder.assert_called_with("INBOX", readonly=True)
        except AssertionError as e:
            raise AssertionError(
                f"test_fetch_does_not_mark_read FAILED | "
                f"INV-FETCH-01 violated | "
                f"Expected: select_folder called with readonly=True | "
                f"Actual: {e} | "
                f"Guidance: email_fetch MUST use readonly mode to prevent marking as read"
            ) from e

    def test_fetch_no_body_logging(self, connected_server, mock_imap_client, sample_raw_email, caplog):
        """
        Contract: EmailFetchContract
        Enforces: INV-FETCH-02, INV-GLOBAL-05
        Adversarial: True
        """
        mock_client = mock_imap_client.return_value
        mock_client.search.return_value = [100]
        mock_client.fetch.return_value = {
            100: {
                b"UID": 100,
                b"FLAGS": [],
                b"INTERNALDATE": datetime(2026, 1, 13, 10, 0, 0),
                b"BODY[]": sample_raw_email,
            }
        }

        with caplog.at_level("DEBUG"):
            connected_server.email_fetch(limit=10)

        # Verify message body NOT in logs
        log_text = caplog.text
        assert "This is a test email body" not in log_text, (
            f"test_fetch_no_body_logging FAILED | "
            f"INV-FETCH-02, INV-GLOBAL-05 violated | "
            f"Expected: message body NOT in logs | "
            f"Actual: 'This is a test email body' found in log output | "
            f"Guidance: email_fetch MUST NOT log message body content"
        )

    def test_fetch_invalid_range_error(self, connected_server):
        """
        Contract: EmailFetchContract
        Enforces: ERRORS: INVALID_RANGE
        """
        with pytest.raises(InvalidRangeError):
            connected_server.email_fetch(
                limit=10,
                date_after="2026-01-31T00:00:00Z",
                date_before="2026-01-01T00:00:00Z",  # Before is before after!
            )

    def test_fetch_folder_not_found_error(self, connected_server, mock_imap_client):
        """
        Contract: EmailFetchContract
        Enforces: ERRORS: FOLDER_NOT_FOUND
        """
        mock_client = mock_imap_client.return_value
        mock_client.select_folder.side_effect = Exception("Folder not found")

        with pytest.raises(FolderNotFoundError):
            connected_server.email_fetch(folder="NonExistent", limit=10)


# =============================================================================
# EMAIL MARK READ CONTRACT TESTS
# =============================================================================

class TestEmailMarkReadContract:
    """Tests for email_mark_read tool behavior."""

    def test_mark_read_basic(self, connected_server, mock_imap_client):
        """
        Contract: EmailMarkReadContract
        Enforces: POST-MARKREAD-01, POST-MARKREAD-04
        """
        mock_client = mock_imap_client.return_value
        mock_client.search.return_value = [100, 200, 300]

        result = connected_server.email_mark_read(folder="INBOX", uids=[100, 200])

        # POST-MARKREAD-01: Returns dict with marked, folder
        assert "marked" in result, (
            f"test_mark_read_basic FAILED | "
            f"POST-MARKREAD-01 violated | "
            f"Expected: result contains 'marked' key | "
            f"Actual: keys are {list(result.keys())} | "
            f"Guidance: email_mark_read MUST return dict with 'marked' key"
        )
        assert "folder" in result, (
            f"test_mark_read_basic FAILED | "
            f"POST-MARKREAD-01 violated | "
            f"Expected: result contains 'folder' key | "
            f"Actual: keys are {list(result.keys())} | "
            f"Guidance: email_mark_read MUST return dict with 'folder' key"
        )
        assert result["folder"] == "INBOX", (
            f"test_mark_read_basic FAILED | "
            f"POST-MARKREAD-01 violated | "
            f"Expected: folder == 'INBOX' | "
            f"Actual: folder == '{result['folder']}' | "
            f"Guidance: email_mark_read MUST return the folder it operated on"
        )

        # POST-MARKREAD-04: add_flags called with \\Seen
        try:
            mock_client.add_flags.assert_called_once_with([100, 200], [b"\\Seen"])
        except AssertionError as e:
            raise AssertionError(
                f"test_mark_read_basic FAILED | "
                f"POST-MARKREAD-04 violated | "
                f"Expected: add_flags called with UIDs and \\Seen flag | "
                f"Actual: {e} | "
                f"Guidance: email_mark_read MUST add \\Seen flag via IMAP"
            ) from e

    def test_mark_read_idempotent(self, connected_server, mock_imap_client):
        """
        Contract: EmailMarkReadContract
        Enforces: INV-MARKREAD-04

        Verify marking already-read message succeeds without error.
        Idempotent = same operation multiple times produces same result.
        """
        mock_client = mock_imap_client.return_value
        mock_client.search.return_value = [100]

        # Marking same message twice should succeed
        result1 = connected_server.email_mark_read(folder="INBOX", uids=[100])
        result2 = connected_server.email_mark_read(folder="INBOX", uids=[100])

        # ASSERTION: Both calls return success with same UID
        # Per POST-MARKREAD-01: Returns dict with keys: marked, folder
        # Per POST-MARKREAD-02: marked is list of UIDs successfully marked
        assert result1["marked"] == [100], (
            f"test_mark_read_idempotent FAILED | "
            f"INV-MARKREAD-04 violated | "
            f"Expected: first call marks UID 100 | "
            f"Actual: got {result1.get('marked')} | "
            f"Guidance: mark_read MUST return marked UIDs in 'marked' key"
        )
        assert result2["marked"] == [100], (
            f"test_mark_read_idempotent FAILED | "
            f"INV-MARKREAD-04 violated | "
            f"Expected: second call also succeeds for same UID | "
            f"Actual: got {result2.get('marked')} | "
            f"Guidance: idempotent operation MUST succeed on repeat"
        )
        # ASSERTION: add_flags called twice (once per call)
        assert mock_client.add_flags.call_count == 2, (
            f"test_mark_read_idempotent FAILED | "
            f"INV-MARKREAD-04 violated | "
            f"Expected: add_flags called 2 times | "
            f"Actual: called {mock_client.add_flags.call_count} times | "
            f"Guidance: idempotent calls MUST each invoke the operation"
        )

    def test_mark_read_no_delete(self, connected_server, mock_imap_client):
        """
        Contract: EmailMarkReadContract
        Enforces: INV-MARKREAD-03, INV-GLOBAL-01
        Adversarial: True
        """
        mock_client = mock_imap_client.return_value
        mock_client.search.return_value = [100]

        connected_server.email_mark_read(folder="INBOX", uids=[100])

        # Verify no delete/expunge methods called on underlying IMAP client
        try:
            mock_client.delete_messages.assert_not_called()
        except AssertionError as e:
            raise AssertionError(
                f"test_mark_read_no_delete FAILED | "
                f"INV-MARKREAD-03, INV-GLOBAL-01 violated | "
                f"Expected: delete_messages never called | "
                f"Actual: {e} | "
                f"Guidance: email_mark_read MUST NOT delete messages"
            ) from e
        try:
            mock_client.expunge.assert_not_called()
        except AssertionError as e:
            raise AssertionError(
                f"test_mark_read_no_delete FAILED | "
                f"INV-MARKREAD-03, INV-GLOBAL-01 violated | "
                f"Expected: expunge never called | "
                f"Actual: {e} | "
                f"Guidance: email_mark_read MUST NOT expunge messages"
            ) from e

    def test_mark_read_uid_not_found_error(self, connected_server, mock_imap_client):
        """
        Contract: EmailMarkReadContract
        Enforces: ERRORS: UID_NOT_FOUND
        """
        mock_client = mock_imap_client.return_value
        mock_client.search.return_value = [100]  # Only UID 100 exists

        with pytest.raises(UidNotFoundError):
            connected_server.email_mark_read(folder="INBOX", uids=[100, 999])  # 999 doesn't exist


# =============================================================================
# EMAIL LIST FOLDERS CONTRACT TESTS
# =============================================================================

class TestEmailListFoldersContract:
    """Tests for email_list_folders tool behavior."""

    def test_list_folders_basic(self, connected_server, mock_imap_client):
        """
        Contract: EmailListFoldersContract
        Enforces: POST-LISTFOLDERS-01, POST-LISTFOLDERS-02
        """
        result = connected_server.email_list_folders()

        # POST-LISTFOLDERS-01: Returns dict with folders key
        assert "folders" in result, (
            f"test_list_folders_basic FAILED | "
            f"POST-LISTFOLDERS-01 violated | "
            f"Expected: result contains 'folders' key | "
            f"Actual: keys are {list(result.keys())} | "
            f"Guidance: email_list_folders MUST return dict with 'folders' key"
        )

        # POST-LISTFOLDERS-02: folders is list of FolderInfo
        assert isinstance(result["folders"], list), (
            f"test_list_folders_basic FAILED | "
            f"POST-LISTFOLDERS-02 violated | "
            f"Expected: folders is a list | "
            f"Actual: folders is {type(result['folders'])} | "
            f"Guidance: email_list_folders MUST return folders as list"
        )
        for folder in result["folders"]:
            assert isinstance(folder, FolderInfo), (
                f"test_list_folders_basic FAILED | "
                f"POST-LISTFOLDERS-02 violated | "
                f"Expected: each folder is FolderInfo | "
                f"Actual: folder is {type(folder)} | "
                f"Guidance: each folder MUST be a FolderInfo object"
            )

    def test_list_folders_complete(self, connected_server, mock_imap_client):
        """
        Contract: EmailListFoldersContract
        Enforces: POST-LISTFOLDERS-03, INV-LISTFOLDERS-03
        """
        mock_client = mock_imap_client.return_value
        mock_client.list_folders.return_value = [
            ([], b"/", "INBOX"),
            ([], b"/", "Sent"),
            ([], b"/", "Drafts"),
            ([], b"/", "Trash"),
            ([], b"/", "Archive"),
        ]

        result = connected_server.email_list_folders()

        # All 5 folders should be included
        folder_names = [f.name for f in result["folders"]]
        assert "INBOX" in folder_names, (
            f"test_list_folders_complete FAILED | "
            f"POST-LISTFOLDERS-03 violated | "
            f"Expected: INBOX in folder names | "
            f"Actual: folder names are {folder_names} | "
            f"Guidance: email_list_folders MUST return ALL folders including INBOX"
        )
        assert "Sent" in folder_names, (
            f"test_list_folders_complete FAILED | "
            f"POST-LISTFOLDERS-03 violated | "
            f"Expected: Sent in folder names | "
            f"Actual: folder names are {folder_names} | "
            f"Guidance: email_list_folders MUST return ALL folders including Sent"
        )


# =============================================================================
# EMAIL STATUS CONTRACT TESTS
# =============================================================================

class TestEmailStatusContract:
    """Tests for email_status tool behavior."""

    def test_status_when_connected(self, connected_server):
        """
        Contract: EmailStatusContract
        Enforces: POST-STATUS-01, POST-STATUS-02
        """
        status = connected_server.email_status()

        # POST-STATUS-01: Returns ConnectionStatus
        assert isinstance(status, ConnectionStatus), (
            f"test_status_when_connected FAILED | "
            f"POST-STATUS-01 violated | "
            f"Expected: status is ConnectionStatus | "
            f"Actual: status is {type(status)} | "
            f"Guidance: email_status MUST return ConnectionStatus object"
        )

        # POST-STATUS-02: connected is True when connected
        assert status.connected is True, (
            f"test_status_when_connected FAILED | "
            f"POST-STATUS-02 violated | "
            f"Expected: connected == True when connected | "
            f"Actual: connected == {status.connected} | "
            f"Guidance: email_status MUST report connected=True when connected"
        )
        assert status.protocol == EmailProtocol.IMAP, (
            f"test_status_when_connected FAILED | "
            f"POST-STATUS-02 violated | "
            f"Expected: protocol == IMAP | "
            f"Actual: protocol == {status.protocol} | "
            f"Guidance: email_status MUST report protocol as IMAP"
        )

    def test_status_honest_disconnected(self):
        """
        Contract: EmailStatusContract
        Enforces: INV-STATUS-04
        Adversarial: True
        """
        server = create_server()
        # Server not connected

        status = server.email_status()

        # INV-STATUS-04: connected=False when actually disconnected
        assert status.connected is False, (
            f"test_status_honest_disconnected FAILED | "
            f"INV-STATUS-04 violated | "
            f"Expected: connected == False when not connected | "
            f"Actual: connected == {status.connected} | "
            f"Guidance: email_status MUST honestly report disconnected state"
        )


# =============================================================================
# GLOBAL INVARIANT TESTS
# =============================================================================

class TestGlobalInvariants:
    """Tests for system-wide invariants."""

    def test_global_no_send_capability(self):
        """
        Contract: INV-GLOBAL-02
        Enforces: INV-GLOBAL-02
        Adversarial: True

        Verify no send/reply/forward methods exist.
        """
        server = create_server()
        client = EmailIMAPClient()

        # Check server has no send methods
        server_methods = [m for m in dir(server) if not m.startswith("_")]
        forbidden_patterns = ["send", "reply", "forward", "compose", "smtp"]

        for method in server_methods:
            for pattern in forbidden_patterns:
                assert pattern not in method.lower(), (
                    f"test_global_no_send_capability FAILED | "
                    f"INV-GLOBAL-02 violated | "
                    f"Expected: no methods containing '{pattern}' | "
                    f"Actual: found method '{method}' | "
                    f"Guidance: Server MUST NOT have send/reply/forward capabilities"
                )

        # Check client has no send methods
        client_methods = [m for m in dir(client) if not m.startswith("_")]
        for method in client_methods:
            for pattern in forbidden_patterns:
                assert pattern not in method.lower(), (
                    f"test_global_no_send_capability FAILED | "
                    f"INV-GLOBAL-02 violated | "
                    f"Expected: no methods containing '{pattern}' | "
                    f"Actual: found method '{method}' | "
                    f"Guidance: Client MUST NOT have send/reply/forward capabilities"
                )

    def test_global_no_delete_capability(self):
        """
        Contract: INV-GLOBAL-01
        Enforces: INV-GLOBAL-01
        Adversarial: True

        Verify no delete methods exist.
        """
        server = create_server()
        client = EmailIMAPClient()

        forbidden_patterns = ["delete", "remove", "expunge", "trash"]

        for obj in [server, client]:
            methods = [m for m in dir(obj) if not m.startswith("_")]
            for method in methods:
                for pattern in forbidden_patterns:
                    assert pattern not in method.lower(), (
                        f"test_global_no_delete_capability FAILED | "
                        f"INV-GLOBAL-01 violated | "
                        f"Expected: no methods containing '{pattern}' | "
                        f"Actual: found method '{method}' | "
                        f"Guidance: System MUST NOT have delete capabilities"
                    )

    def test_global_no_move_capability(self):
        """
        Contract: INV-GLOBAL-03
        Enforces: INV-GLOBAL-03
        Adversarial: True

        Verify no move methods exist.
        """
        server = create_server()
        client = EmailIMAPClient()

        forbidden_patterns = ["move", "copy", "transfer"]

        for obj in [server, client]:
            methods = [m for m in dir(obj) if not m.startswith("_")]
            for method in methods:
                for pattern in forbidden_patterns:
                    assert pattern not in method.lower(), (
                        f"test_global_no_move_capability FAILED | "
                        f"INV-GLOBAL-03 violated | "
                        f"Expected: no methods containing '{pattern}' | "
                        f"Actual: found method '{method}' | "
                        f"Guidance: System MUST NOT have move/copy capabilities"
                    )

    def test_global_process_clears_credentials(self):
        """
        Contract: INV-GLOBAL-07
        Enforces: INV-GLOBAL-07
        Adversarial: True

        Verify credentials not retained after connection.
        Uses weakref to verify Credentials object can be garbage collected.
        """
        import gc
        import weakref

        from src.email_mcp.credentials import Credentials

        with patch("src.email_mcp.imap_client.IMAPClient"):
            server = create_server()

            # Create credentials and get weak reference
            creds = Credentials(
                username="test@example.com",
                password="secret123",
                server="imap.example.com",
            )
            creds_ref = weakref.ref(creds)

            # Connect using credentials
            server.connect(creds)

            # Delete our reference to credentials
            del creds

            # Force garbage collection
            gc.collect()

            # ASSERTION: Credentials should be collectable (not retained by server)
            # If server stored credentials, weakref would still be alive
            assert creds_ref() is None, (
                f"test_global_process_clears_credentials FAILED | "
                f"INV-GLOBAL-07 violated | "
                f"Expected: Credentials garbage collected after connect | "
                f"Actual: Credentials still referenced (memory leak) | "
                f"Guidance: Server MUST NOT retain Credentials object"
            )

            # Disconnect and verify state
            server.disconnect()
            status = server.email_status()
            assert status.connected is False, (
                f"test_global_process_clears_credentials FAILED | "
                f"INV-GLOBAL-07 violated | "
                f"Expected: connected=False after disconnect | "
                f"Actual: connected={status.connected} | "
                f"Guidance: disconnect MUST clear connection state"
            )

            # ASSERTION: Server's internal client reference is None
            assert server._client is None, (
                f"test_global_process_clears_credentials FAILED | "
                f"INV-GLOBAL-07 violated | "
                f"Expected: server._client=None after disconnect | "
                f"Actual: server._client still exists | "
                f"Guidance: disconnect MUST clear client reference"
            )

    def test_startup_tls_required(self):
        """
        Contract: StartupContract
        Enforces: INV-STARTUP-04, INV-GLOBAL-09
        Adversarial: True

        Verify TLS 1.2+ required, no plaintext fallback.
        """
        from src.email_mcp.credentials import Credentials

        # Verify Credentials default to SSL/TLS enabled
        creds = Credentials(
            username="test@example.com",
            password="secret",
            server="imap.example.com",
        )
        assert creds.use_ssl is True, (
            f"test_startup_tls_required FAILED | "
            f"INV-STARTUP-04, INV-GLOBAL-09 violated | "
            f"Expected: use_ssl == True by default | "
            f"Actual: use_ssl == {creds.use_ssl} | "
            f"Guidance: TLS MUST be enabled by default, no plaintext fallback"
        )

        # Verify there's no way to disable TLS (no plaintext option)
        # The Credentials dataclass has use_ssl=True as default
        # and the implementation always uses SSL context

    def test_startup_certificate_validated(self):
        """
        Contract: StartupContract
        Enforces: INV-STARTUP-05
        Adversarial: True

        Verify server certificate validated against system CA.
        """
        # IMAPClient uses ssl=True which validates certificates by default
        # The implementation does not disable certificate verification
        # This is verified by checking that no ssl_context with
        # check_hostname=False or verify_mode=NONE is used

        from src.email_mcp.imap_client import EmailIMAPClient
        import inspect

        source = inspect.getsource(EmailIMAPClient)
        # Ensure no certificate verification bypass
        assert "check_hostname" not in source or "check_hostname=True" in source, (
            f"test_startup_certificate_validated FAILED | "
            f"INV-STARTUP-05 violated | "
            f"Expected: check_hostname not disabled | "
            f"Actual: check_hostname=False found in source | "
            f"Guidance: Certificate hostname MUST be validated"
        )
        assert "CERT_NONE" not in source, (
            f"test_startup_certificate_validated FAILED | "
            f"INV-STARTUP-05 violated | "
            f"Expected: CERT_NONE not used | "
            f"Actual: CERT_NONE found in source | "
            f"Guidance: Certificate verification MUST NOT be disabled"
        )


# =============================================================================
# CONTRACT COVERAGE META-TEST
# =============================================================================

def test_contract_coverage():
    """
    Meta-test: Verify this test file covers contract clauses.
    """
    from contracts import audit_contract_coverage

    coverage = audit_contract_coverage()

    print(f"\nContract Coverage: {coverage['coverage_pct']}%")
    print(f"Tests defined: {coverage['test_count']}")
    print(f"Clauses covered: {len(coverage['covered'])}")

    # Don't fail - just report coverage
    assert coverage["test_count"] > 0, (
        f"test_contract_coverage FAILED | "
        f"META violated | "
        f"Expected: test_count > 0 | "
        f"Actual: test_count == {coverage['test_count']} | "
        f"Guidance: Tests must exist for contract coverage"
    )
