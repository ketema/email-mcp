"""
IMAPClient External Dependency Contract
=======================================

CL10 CONTRACT: This file defines the expected interface behavior from
the external imapclient library (imapclient.IMAPClient) as used by
this codebase.

PURPOSE: Mocks MUST be derived from this contract. If imapclient
changes behavior, contract verification tests will detect drift.

AUTHORITY: This is the SINGULAR authoritative contract for IMAPClient
behavior expectations in this codebase (CL12-C).

NOTE: This is a contract for an EXTERNAL dependency, not internal code.
It documents what THIS codebase expects from imapclient, not what
imapclient guarantees.
"""

from dataclasses import dataclass
from typing import Any


# =============================================================================
# TYPE DEFINITIONS (Expected from imapclient)
# =============================================================================

@dataclass
class FolderTuple:
    """
    Expected format for list_folders() response items.

    Format: ((flags,), delimiter, name)
    - flags: tuple of bytes flags (e.g., b'\\HasNoChildren')
    - delimiter: bytes separator (e.g., b'/')
    - name: str folder name
    """

    flags: tuple[bytes, ...]
    delimiter: bytes
    name: str


@dataclass
class FolderStatus:
    """
    Expected format for folder_status() response.

    Dict with keys: MESSAGES, UNSEEN, UIDVALIDITY, UIDNEXT
    All values are integers.
    """

    MESSAGES: int
    UNSEEN: int
    UIDVALIDITY: int
    UIDNEXT: int


@dataclass
class SelectFolderResponse:
    """
    Expected format for select_folder() response.

    Dict with keys: UIDVALIDITY, UIDNEXT, EXISTS, etc.
    """

    UIDVALIDITY: int
    UIDNEXT: int
    EXISTS: int


# =============================================================================
# IMAPCLIENT CONTRACT
# =============================================================================

class IMAPClientContract:
    """
    Contract for imapclient.IMAPClient expected behavior.

    PRE/POST/INV clauses define what THIS codebase expects from the library.
    Implementation (mocks) MUST adhere to these expectations.
    """

    # -------------------------------------------------------------------------
    # CONNECTION METHODS
    # -------------------------------------------------------------------------

    def login(self, username: str, password: str) -> bytes:
        """
        Authenticate with server.

        PRE-LOGIN-01: username is non-empty string
        PRE-LOGIN-02: password is non-empty string
        POST-LOGIN-01: Returns bytes response on success
        ERRORS-LOGIN-01: Raises LoginError on auth failure
        """
        ...

    def logout(self) -> bytes:
        """
        Disconnect from server.

        PRE-LOGOUT-01: Connection established
        POST-LOGOUT-01: Returns bytes response
        POST-LOGOUT-02: Connection closed
        INV-LOGOUT-01: Safe to call multiple times
        """
        ...

    # -------------------------------------------------------------------------
    # FOLDER METHODS
    # -------------------------------------------------------------------------

    def list_folders(
        self, directory: str = "", pattern: str = "*"
    ) -> list[tuple[tuple[bytes, ...], bytes, str]]:
        """
        List folders matching pattern.

        PRE-LISTFOLDERS-01: Connection established
        POST-LISTFOLDERS-01: Returns list of folder tuples
        POST-LISTFOLDERS-02: Each tuple: ((flags,), delimiter, name)
        INV-LISTFOLDERS-01: Read-only operation
        """
        ...

    def folder_status(
        self, folder: str, what: list[str] | None = None
    ) -> dict[str, int]:
        """
        Get folder status (message counts, etc).

        PRE-FOLDERSTATUS-01: Connection established
        PRE-FOLDERSTATUS-02: folder exists
        POST-FOLDERSTATUS-01: Returns dict with MESSAGES, UNSEEN, UIDVALIDITY
        POST-FOLDERSTATUS-02: All values are integers
        ERRORS-FOLDERSTATUS-01: Raises error if folder not found
        """
        ...

    def select_folder(self, folder: str, readonly: bool = False) -> dict[str, Any]:
        """
        Select folder for operations.

        PRE-SELECTFOLDER-01: Connection established
        PRE-SELECTFOLDER-02: folder exists
        POST-SELECTFOLDER-01: Returns dict with UIDVALIDITY, UIDNEXT
        POST-SELECTFOLDER-02: Folder becomes current for search/fetch
        INV-SELECTFOLDER-01: readonly=True prevents modifications
        ERRORS-SELECTFOLDER-01: Raises error if folder not found
        """
        ...

    # -------------------------------------------------------------------------
    # MESSAGE METHODS
    # -------------------------------------------------------------------------

    def search(
        self, criteria: str | list[str] = "ALL", charset: str | None = None
    ) -> list[int]:
        """
        Search for messages matching criteria.

        PRE-SEARCH-01: Folder selected
        POST-SEARCH-01: Returns list of UIDs (integers)
        POST-SEARCH-02: Empty list if no matches
        INV-SEARCH-01: Read-only operation
        """
        ...

    def fetch(
        self, messages: list[int] | str, data: list[str], modifiers: list[str] | None = None
    ) -> dict[int, dict[str, Any]]:
        """
        Fetch message data.

        PRE-FETCH-01: Folder selected
        PRE-FETCH-02: messages are valid UIDs or UID range string
        POST-FETCH-01: Returns dict keyed by UID
        POST-FETCH-02: Each value contains requested data keys
        POST-FETCH-03: BODY.PEEK[] does NOT set \\Seen flag
        INV-FETCH-01: BODY.PEEK maintains read-only
        """
        ...

    def add_flags(self, messages: list[int], flags: list[bytes]) -> dict[int, tuple[bytes, ...]]:
        """
        Add flags to messages.

        PRE-ADDFLAGS-01: Folder selected with write access
        PRE-ADDFLAGS-02: messages are valid UIDs
        POST-ADDFLAGS-01: Returns dict of UID -> new flags
        POST-ADDFLAGS-02: Specified flags added to each message
        INV-ADDFLAGS-01: Idempotent - adding existing flag is no-op
        """
        ...


# =============================================================================
# TEST CASES FOR CONTRACT VERIFICATION
# =============================================================================

CONTRACT_TEST_CASES = {
    "login_success": {
        "method": "login",
        "args": {"username": "test@example.com", "password": "secret"},
        "expected": bytes,
        "contract": ["PRE-LOGIN-01", "PRE-LOGIN-02", "POST-LOGIN-01"],
    },
    "list_folders_format": {
        "method": "list_folders",
        "args": {},
        "expected_type": list,
        "expected_item_format": "tuple[tuple[bytes, ...], bytes, str]",
        "contract": ["POST-LISTFOLDERS-01", "POST-LISTFOLDERS-02"],
    },
    "search_returns_uids": {
        "method": "search",
        "args": {"criteria": "ALL"},
        "expected_type": list,
        "expected_item_type": int,
        "contract": ["POST-SEARCH-01", "POST-SEARCH-02"],
    },
    "fetch_body_peek_readonly": {
        "method": "fetch",
        "args": {"messages": [1], "data": ["BODY.PEEK[]"]},
        "invariant": "\\Seen flag NOT added",
        "contract": ["POST-FETCH-03", "INV-FETCH-01"],
    },
    "add_flags_idempotent": {
        "method": "add_flags",
        "args": {"messages": [1], "flags": [b"\\Seen"]},
        "invariant": "Calling twice produces same result",
        "contract": ["INV-ADDFLAGS-01"],
    },
}
