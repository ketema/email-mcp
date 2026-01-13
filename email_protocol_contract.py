"""
Email Protocol MCP Server Contract
==================================

REQ-2026-002: Dumb pipe MCP tool for AI agents to access email via IMAP/POP3.

This contract defines the behavioral specification for all public interfaces.
Implementation SHALL perform ONLY declared behaviors (Strict Constructionism).

CONSTITUTIONAL REFERENCE:
- CL12: Design by Contract (PRE/POST/INV/ERRORS mandatory)
- CL10: Mock Derivation (all mocks must derive from this contract)
- CL12-E: Test Traceability (all tests must cite clause IDs)

AUTHORITY: This file is the SINGLE authoritative source for email MCP behavior.
"""

from dataclasses import dataclass
from typing import Protocol, runtime_checkable
from enum import Enum, auto


# =============================================================================
# DOMAIN TYPES
# =============================================================================

class EmailProtocol(Enum):
    """Supported email protocols."""
    IMAP = auto()
    POP3 = auto()


@dataclass(frozen=True)
class EmailAddress:
    """Structured email address."""
    name: str | None
    address: str


@dataclass(frozen=True)
class Attachment:
    """Email attachment metadata and content."""
    filename: str
    mime_type: str
    size_bytes: int
    content_base64: str


@dataclass(frozen=True)
class EmailMessage:
    """Complete email message structure per SMTP/IMAP specification."""
    uid: int
    message_id: str
    thread_id: str | None
    from_addr: EmailAddress
    to_addrs: list[EmailAddress]
    cc_addrs: list[EmailAddress]
    bcc_addrs: list[EmailAddress]
    subject: str
    date: str  # ISO8601
    internal_date: str  # ISO8601
    body_plain: str | None
    body_html: str | None
    attachments: list[Attachment]
    flags: list[str]
    in_reply_to: str | None
    references: list[str]


@dataclass(frozen=True)
class FolderInfo:
    """Mailbox folder metadata."""
    name: str
    message_count: int
    unread_count: int
    uidvalidity: int


@dataclass(frozen=True)
class ConnectionStatus:
    """Current connection state."""
    connected: bool
    protocol: EmailProtocol
    server: str
    uptime_seconds: int


# =============================================================================
# ERROR TYPES
# =============================================================================

class EmailMCPError(Exception):
    """Base error for all Email MCP operations."""
    code: str
    message: str


class BiosecretDeniedError(EmailMCPError):
    """
    ERRORS-STARTUP-01: User cancelled biometric prompt.
    
    RECOVERY: Fatal. Process must exit. Agent restarts MCP to retry.
    """
    code = "BIOSECRET_DENIED"


class BiosecretNotFoundError(EmailMCPError):
    """
    ERRORS-STARTUP-02: No credentials stored under expected keychain key.
    
    RECOVERY: Fatal. User must store credentials via biosecret before retry.
    """
    code = "BIOSECRET_NOT_FOUND"


class AuthFailedError(EmailMCPError):
    """
    ERRORS-STARTUP-03: Credentials valid in keychain but rejected by mail server.
    
    RECOVERY: Fatal. User must update stored credentials.
    """
    code = "AUTH_FAILED"


class ConnectionFailedError(EmailMCPError):
    """
    ERRORS-STARTUP-04: Network unreachable or host not found.
    
    RECOVERY: Fatal. Check network connectivity and retry.
    """
    code = "CONNECTION_FAILED"


class NotConnectedError(EmailMCPError):
    """
    ERRORS-TOOL-01: Startup failed or connection dropped mid-session.
    
    RECOVERY: Agent must restart MCP process.
    """
    code = "NOT_CONNECTED"


class FolderNotFoundError(EmailMCPError):
    """
    ERRORS-TOOL-02: Specified folder does not exist on server.
    
    RECOVERY: Agent should call email_list_folders to get valid folder names.
    """
    code = "FOLDER_NOT_FOUND"


class InvalidRangeError(EmailMCPError):
    """
    ERRORS-TOOL-03: date_after is greater than date_before.
    
    RECOVERY: Agent must correct date parameters.
    """
    code = "INVALID_RANGE"


class UidNotFoundError(EmailMCPError):
    """
    ERRORS-TOOL-04: One or more UIDs do not exist in folder.
    
    RECOVERY: Agent should refresh message list; UIDs may have been
    deleted by external client.
    """
    code = "UID_NOT_FOUND"


# =============================================================================
# STARTUP CONTRACT
# =============================================================================

@runtime_checkable
class StartupContract(Protocol):
    """
    MCP Process Startup Behavior
    
    Startup occurs automatically when MCP process is launched.
    Agent does not call this directly; it happens before tools are available.
    
    SEQUENCE:
    1. MCP process starts
    2. MCP invokes biosecret for credential retrieval
    3. User authenticates via Touch ID / biometric
    4. Credentials loaded into memory
    5. IMAP/POP3 connection established
    6. MCP ready to accept tool calls
    
    PRE-STARTUP-01: biosecret CLI is available in PATH
    PRE-STARTUP-02: User has stored email credentials in macOS Keychain
                    under key "email-mcp/{account_id}"
    PRE-STARTUP-03: MCP process has entitlement to invoke biosecret
    PRE-STARTUP-04: Network connectivity to mail server is available
    
    POST-STARTUP-01: On successful biometric auth, credentials exist in memory
    POST-STARTUP-02: IMAP or POP3 connection is established and authenticated
    POST-STARTUP-03: MCP server is ready to accept tool calls
    POST-STARTUP-04: connection_status.connected == True
    
    INV-STARTUP-01 (Credential Isolation): Credentials held in memory only,
                    never written to disk, environment variables, or logs
    INV-STARTUP-02 (Single Session): One authenticated session per process
    INV-STARTUP-03 (Fatal Errors): All startup errors terminate process
    
    ERRORS:
    - BIOSECRET_DENIED: User cancelled biometric prompt → process exits
    - BIOSECRET_NOT_FOUND: No credentials under expected key → process exits
    - AUTH_FAILED: Server rejected credentials → process exits
    - CONNECTION_FAILED: Network unreachable → process exits
    """
    pass


# =============================================================================
# TOOL CONTRACTS
# =============================================================================

@runtime_checkable
class EmailFetchContract(Protocol):
    """
    Tool: email_fetch
    
    Retrieve messages from a mailbox folder with filtering options.
    
    PRE-FETCH-01: MCP process startup completed successfully (connected)
    PRE-FETCH-02: folder is valid folder name returned by email_list_folders,
                  or "INBOX" (always valid)
    PRE-FETCH-03: If provided, date_after is valid ISO8601 datetime string
    PRE-FETCH-04: If provided, date_before is valid ISO8601 datetime string
    PRE-FETCH-05: If both date_after and date_before provided,
                  date_after <= date_before
    PRE-FETCH-06: limit is positive integer, 1 <= limit <= 100
    PRE-FETCH-07: If provided, uid_gt is non-negative integer
    
    POST-FETCH-01: Returns dict with keys: messages, folder, uidvalidity, next_uid
    POST-FETCH-02: messages is list of EmailMessage matching ALL filter criteria
    POST-FETCH-03: len(messages) <= limit
    POST-FETCH-04: All returned messages have uid > uid_gt (if uid_gt provided)
    POST-FETCH-05: All returned messages have date >= date_after (if provided)
    POST-FETCH-06: All returned messages have date <= date_before (if provided)
    POST-FETCH-07: messages ordered by uid ascending
    POST-FETCH-08: uidvalidity matches current folder UIDVALIDITY
    POST-FETCH-09: next_uid is server's predicted next UID for folder
    
    INV-FETCH-01 (Read-Only): Fetch MUST NOT modify message flags
    INV-FETCH-02 (No Side Effects): No logging of message bodies or attachments
    INV-FETCH-03 (Deterministic): Same inputs + same server state = same outputs
    INV-FETCH-04 (State Isolation): Fetch does not affect other folders
    INV-FETCH-05 (Exception Safety): On error, no partial state changes
    
    ERRORS:
    - NOT_CONNECTED: Startup failed or connection dropped
    - FOLDER_NOT_FOUND: Specified folder does not exist
    - INVALID_RANGE: date_after > date_before
    """
    
    def email_fetch(
        self,
        *,
        folder: str = "INBOX",
        date_after: str | None = None,
        date_before: str | None = None,
        limit: int,
        uid_gt: int | None = None,
    ) -> dict:
        """Fetch messages from folder with filtering."""
        ...


@runtime_checkable
class EmailMarkReadContract(Protocol):
    """
    Tool: email_mark_read
    
    Mark specified messages as read (set \\Seen flag).
    
    PRE-MARKREAD-01: MCP process startup completed successfully (connected)
    PRE-MARKREAD-02: folder is valid folder name
    PRE-MARKREAD-03: uids is non-empty list of positive integers
    PRE-MARKREAD-04: All UIDs in uids exist in specified folder
    
    POST-MARKREAD-01: Returns dict with keys: marked, folder
    POST-MARKREAD-02: marked is list of UIDs that were successfully marked
    POST-MARKREAD-03: len(marked) == len(uids) (all or nothing)
    POST-MARKREAD-04: All messages with UIDs in marked now have \\Seen flag
    
    INV-MARKREAD-01 (Targeted Mutation): ONLY \\Seen flag modified
    INV-MARKREAD-02 (Scope Isolation): Only specified UIDs affected
    INV-MARKREAD-03 (No Delete): Message count unchanged after operation
    INV-MARKREAD-04 (Idempotent): Marking already-read message succeeds
    INV-MARKREAD-05 (Exception Safety): On error, no UIDs partially marked
    
    ERRORS:
    - NOT_CONNECTED: Startup failed or connection dropped
    - FOLDER_NOT_FOUND: Specified folder does not exist
    - UID_NOT_FOUND: One or more UIDs do not exist (external deletion)
    """
    
    def email_mark_read(
        self,
        *,
        folder: str,
        uids: list[int],
    ) -> dict:
        """Mark messages as read."""
        ...


@runtime_checkable
class EmailListFoldersContract(Protocol):
    """
    Tool: email_list_folders
    
    List all available mailbox folders with metadata.
    
    PRE-LISTFOLDERS-01: MCP process startup completed successfully (connected)
    
    POST-LISTFOLDERS-01: Returns dict with key: folders
    POST-LISTFOLDERS-02: folders is list of FolderInfo
    POST-LISTFOLDERS-03: Every folder accessible to authenticated user is included
    POST-LISTFOLDERS-04: message_count and unread_count reflect current server state
    POST-LISTFOLDERS-05: uidvalidity is current UIDVALIDITY for each folder
    
    INV-LISTFOLDERS-01 (Read-Only): No server state modified
    INV-LISTFOLDERS-02 (No Side Effects): No logging, no metrics
    INV-LISTFOLDERS-03 (Complete): All folders returned, no filtering
    INV-LISTFOLDERS-04 (Exception Safety): On error, no partial results
    
    ERRORS:
    - NOT_CONNECTED: Startup failed or connection dropped
    """
    
    def email_list_folders(self) -> dict:
        """List all mailbox folders."""
        ...


@runtime_checkable
class EmailStatusContract(Protocol):
    """
    Tool: email_status
    
    Return current connection status. Health check for agent.
    
    PRE-STATUS-01: MCP process is running (may or may not be connected)
    
    POST-STATUS-01: Returns ConnectionStatus dataclass
    POST-STATUS-02: connected is True iff startup succeeded and connection alive
    POST-STATUS-03: protocol is the active protocol (IMAP or POP3)
    POST-STATUS-04: server is the connected mail server hostname
    POST-STATUS-05: uptime_seconds is seconds since successful startup
    
    INV-STATUS-01 (Read-Only): No server state modified
    INV-STATUS-02 (No Side Effects): No external calls to check status
    INV-STATUS-03 (Always Succeeds): If callable, returns valid status
    INV-STATUS-04 (Honest): connected reflects actual connection state
    
    ERRORS: None
    
    NOTE: If this tool is callable, the process is running. If connected=False,
    startup failed but process hasn't exited yet (edge case during shutdown).
    """
    
    def email_status(self) -> ConnectionStatus:
        """Return connection status."""
        ...


# =============================================================================
# GLOBAL INVARIANTS (Apply to ALL operations)
# =============================================================================

"""
INV-GLOBAL-01 (No Delete): This MCP server MUST NOT delete messages.
             External clients may delete; this is outside MCP scope.

INV-GLOBAL-02 (No Send): MCP server CANNOT send, reply, or forward email.

INV-GLOBAL-03 (No Move): MCP server CANNOT move messages between folders.

INV-GLOBAL-04 (Credential Isolation): Credentials retrieved via biosecret
             at startup, held in memory only, never persisted by MCP.

INV-GLOBAL-05 (No Content Logging): Email bodies and attachments MUST NOT
             appear in MCP server logs under any circumstance.

INV-GLOBAL-06 (Explicit Mutation): Mark-as-read requires explicit call;
             fetching alone does not mutate server state.

INV-GLOBAL-07 (Process Termination Clears Credentials): On process exit
             (normal or crash), all credentials cleared from memory.

INV-GLOBAL-08 (Single Connection): One mail server connection per process.
             No multiplexing, no connection pooling.
"""


# =============================================================================
# THREADING CONTRACT
# =============================================================================

"""
Thread Derivation Rules
-----------------------

Messages are grouped into threads using the following precedence:

1. thread_id derived from FIRST Message-ID in References header chain
2. FALLBACK: In-Reply-To header value
3. FALLBACK: Subject normalization (strip Re:/Fwd:/Fw: prefixes, case-insensitive)

PRE-THREAD-01: Message has at least one of: References, In-Reply-To, or Subject

POST-THREAD-01: thread_id is non-empty string
POST-THREAD-02: Messages with same thread_id belong to same conversation
POST-THREAD-03: thread_id derivation is deterministic (same headers = same thread_id)

INV-THREAD-01: Thread grouping is agent responsibility; MCP returns flat list
INV-THREAD-02: thread_id calculation has no side effects
"""


# =============================================================================
# TEST CASE INDEX (CL12-E Traceability)
# =============================================================================

TEST_CASES = {
    # Startup tests
    "test_startup_biosecret_success": {
        "contract": "StartupContract",
        "enforces": ["POST-STARTUP-01", "POST-STARTUP-02", "POST-STARTUP-03"],
    },
    "test_startup_biosecret_denied": {
        "contract": "StartupContract",
        "enforces": ["ERRORS: BIOSECRET_DENIED"],
    },
    "test_startup_credentials_not_found": {
        "contract": "StartupContract",
        "enforces": ["ERRORS: BIOSECRET_NOT_FOUND"],
    },
    "test_startup_auth_failed": {
        "contract": "StartupContract",
        "enforces": ["ERRORS: AUTH_FAILED"],
    },
    "test_startup_credentials_memory_only": {
        "contract": "StartupContract",
        "enforces": ["INV-STARTUP-01"],
        "adversarial": True,
        "description": "Verify credentials not in env vars, disk, or logs",
    },
    
    # Fetch tests
    "test_fetch_basic": {
        "contract": "EmailFetchContract",
        "enforces": ["POST-FETCH-01", "POST-FETCH-02"],
    },
    "test_fetch_limit_respected": {
        "contract": "EmailFetchContract",
        "enforces": ["POST-FETCH-03"],
    },
    "test_fetch_uid_gt_filter": {
        "contract": "EmailFetchContract",
        "enforces": ["POST-FETCH-04"],
    },
    "test_fetch_date_range_filter": {
        "contract": "EmailFetchContract",
        "enforces": ["POST-FETCH-05", "POST-FETCH-06"],
    },
    "test_fetch_ordering": {
        "contract": "EmailFetchContract",
        "enforces": ["POST-FETCH-07"],
    },
    "test_fetch_does_not_mark_read": {
        "contract": "EmailFetchContract",
        "enforces": ["INV-FETCH-01"],
        "adversarial": True,
        "description": "Verify \\Seen flag unchanged after fetch",
    },
    "test_fetch_no_body_logging": {
        "contract": "EmailFetchContract",
        "enforces": ["INV-FETCH-02", "INV-GLOBAL-05"],
        "adversarial": True,
        "description": "Verify message body not in any log output",
    },
    "test_fetch_invalid_range_error": {
        "contract": "EmailFetchContract",
        "enforces": ["ERRORS: INVALID_RANGE"],
    },
    "test_fetch_folder_not_found_error": {
        "contract": "EmailFetchContract",
        "enforces": ["ERRORS: FOLDER_NOT_FOUND"],
    },
    
    # Mark read tests
    "test_mark_read_basic": {
        "contract": "EmailMarkReadContract",
        "enforces": ["POST-MARKREAD-01", "POST-MARKREAD-04"],
    },
    "test_mark_read_idempotent": {
        "contract": "EmailMarkReadContract",
        "enforces": ["INV-MARKREAD-04"],
    },
    "test_mark_read_no_delete": {
        "contract": "EmailMarkReadContract",
        "enforces": ["INV-MARKREAD-03", "INV-GLOBAL-01"],
        "adversarial": True,
        "description": "Verify message count unchanged after mark_read",
    },
    "test_mark_read_uid_not_found_error": {
        "contract": "EmailMarkReadContract",
        "enforces": ["ERRORS: UID_NOT_FOUND"],
    },
    
    # List folders tests
    "test_list_folders_basic": {
        "contract": "EmailListFoldersContract",
        "enforces": ["POST-LISTFOLDERS-01", "POST-LISTFOLDERS-02"],
    },
    "test_list_folders_complete": {
        "contract": "EmailListFoldersContract",
        "enforces": ["POST-LISTFOLDERS-03", "INV-LISTFOLDERS-03"],
    },
    
    # Status tests
    "test_status_when_connected": {
        "contract": "EmailStatusContract",
        "enforces": ["POST-STATUS-01", "POST-STATUS-02"],
    },
    "test_status_honest_disconnected": {
        "contract": "EmailStatusContract",
        "enforces": ["INV-STATUS-04"],
        "adversarial": True,
        "description": "Verify connected=False when actually disconnected",
    },
    
    # Global invariant tests
    "test_global_no_send_capability": {
        "contract": "INV-GLOBAL-02",
        "enforces": ["INV-GLOBAL-02"],
        "adversarial": True,
        "description": "Verify no send/reply/forward methods exist",
    },
    "test_global_no_delete_capability": {
        "contract": "INV-GLOBAL-01",
        "enforces": ["INV-GLOBAL-01"],
        "adversarial": True,
        "description": "Verify no delete methods exist",
    },
    "test_global_no_move_capability": {
        "contract": "INV-GLOBAL-03",
        "enforces": ["INV-GLOBAL-03"],
        "adversarial": True,
        "description": "Verify no move methods exist",
    },
    "test_global_process_clears_credentials": {
        "contract": "INV-GLOBAL-07",
        "enforces": ["INV-GLOBAL-07"],
        "adversarial": True,
        "description": "Verify credentials not recoverable after process exit",
    },
}


# =============================================================================
# COMPLETION PROMISE
# =============================================================================

"""
COMPLETION PROMISE (Ralph Loop Exit Condition)
==============================================

The Ralph loop is complete when the Constitutional Auditor verifies:

1. StartupContract: biosecret integration works for success and all error paths
2. EmailFetchContract: Filtering by date_range/limit/uid_gt works correctly
3. INV-FETCH-01: Fetch does NOT mark messages as read (adversarial test)
4. EmailMarkReadContract: Sets \\Seen flag on specified UIDs only
5. INV-GLOBAL-01 through INV-GLOBAL-08: All global invariants have adversarial
   tests that FAIL if the invariant is violated
6. INV-GLOBAL-05: No credential or email body appears in any log output
7. All TEST_CASES pass with CL12-E traceability to contract clauses
8. Theater Detection: No test uses range checks for deterministic values

VERDICT CRITERIA:
- Finding count == 0 → ZERO CONSTITUTIONAL VIOLATIONS
- Finding count > 0 → VIOLATIONS FOUND, loop continues
"""
