"""
Email MCP Contract Index
========================

AUTHORITY: This file is the SINGLE authoritative entrypoint for all
Email MCP contracts. Import from here, not from individual contract files.

CONSTITUTIONAL REFERENCE: CL12-C (Single Authoritative Source)
"""

from contracts.email_protocol_contract import (
    # Test Case Index
    TEST_CASES,
    Attachment,
    AuthFailedError,
    BiosecretDeniedError,
    BiosecretNotFoundError,
    CertificateVerificationError,
    ConnectionFailedError,
    ConnectionStatus,
    EmailAddress,
    EmailFetchContract,
    EmailListFoldersContract,
    EmailMarkReadContract,
    # Error Types
    EmailMCPError,
    EmailMessage,
    # Domain Types
    EmailProtocol,
    EmailStatusContract,
    FolderInfo,
    FolderNotFoundError,
    InvalidRangeError,
    NotConnectedError,
    # Contracts (Protocols)
    StartupContract,
    TLSRequiredError,
    TLSRequirement,
    UidNotFoundError,
)

__all__ = [
    # Domain Types
    "EmailProtocol",
    "TLSRequirement",
    "EmailAddress",
    "Attachment",
    "EmailMessage",
    "FolderInfo",
    "ConnectionStatus",
    # Error Types
    "EmailMCPError",
    "BiosecretDeniedError",
    "BiosecretNotFoundError",
    "AuthFailedError",
    "ConnectionFailedError",
    "TLSRequiredError",
    "CertificateVerificationError",
    "NotConnectedError",
    "FolderNotFoundError",
    "InvalidRangeError",
    "UidNotFoundError",
    # Contracts
    "StartupContract",
    "EmailFetchContract",
    "EmailMarkReadContract",
    "EmailListFoldersContract",
    "EmailStatusContract",
    # Test Traceability
    "TEST_CASES",
    # Functions
    "audit_contract_coverage",
]


def audit_contract_coverage() -> dict:
    """
    Audit which contract clauses have test coverage.

    Returns dict with:
    - covered: clauses with at least one test
    - uncovered: clauses with no tests
    - test_count: total tests defined

    Used by constitutional-audit skill.
    """
    covered_clauses = set()
    for test_name, test_info in TEST_CASES.items():
        for clause in test_info.get("enforces", []):
            covered_clauses.add(clause)

    # All PRE/POST/INV/ERRORS clauses from contracts
    all_clauses = set()

    # Startup clauses
    all_clauses.update(
        [
            "PRE-STARTUP-01",
            "PRE-STARTUP-02",
            "PRE-STARTUP-03",
            "PRE-STARTUP-04",
            "PRE-STARTUP-05",
            "PRE-STARTUP-06",
            "POST-STARTUP-01",
            "POST-STARTUP-02",
            "POST-STARTUP-03",
            "POST-STARTUP-04",
            "INV-STARTUP-01",
            "INV-STARTUP-02",
            "INV-STARTUP-03",
            "INV-STARTUP-04",
            "INV-STARTUP-05",
            "ERRORS: BIOSECRET_DENIED",
            "ERRORS: BIOSECRET_NOT_FOUND",
            "ERRORS: AUTH_FAILED",
            "ERRORS: CONNECTION_FAILED",
            "ERRORS: TLS_REQUIRED",
            "ERRORS: CERTIFICATE_VERIFICATION_FAILED",
        ]
    )

    # Fetch clauses
    all_clauses.update(
        [
            "PRE-FETCH-01",
            "PRE-FETCH-02",
            "PRE-FETCH-03",
            "PRE-FETCH-04",
            "PRE-FETCH-05",
            "PRE-FETCH-06",
            "PRE-FETCH-07",
            "POST-FETCH-01",
            "POST-FETCH-02",
            "POST-FETCH-03",
            "POST-FETCH-04",
            "POST-FETCH-05",
            "POST-FETCH-06",
            "POST-FETCH-07",
            "POST-FETCH-08",
            "POST-FETCH-09",
            "INV-FETCH-01",
            "INV-FETCH-02",
            "INV-FETCH-03",
            "INV-FETCH-04",
            "INV-FETCH-05",
            "ERRORS: NOT_CONNECTED",
            "ERRORS: FOLDER_NOT_FOUND",
            "ERRORS: INVALID_RANGE",
        ]
    )

    # Mark read clauses
    all_clauses.update(
        [
            "PRE-MARKREAD-01",
            "PRE-MARKREAD-02",
            "PRE-MARKREAD-03",
            "PRE-MARKREAD-04",
            "POST-MARKREAD-01",
            "POST-MARKREAD-02",
            "POST-MARKREAD-03",
            "POST-MARKREAD-04",
            "INV-MARKREAD-01",
            "INV-MARKREAD-02",
            "INV-MARKREAD-03",
            "INV-MARKREAD-04",
            "INV-MARKREAD-05",
            "ERRORS: UID_NOT_FOUND",
        ]
    )

    # List folders clauses
    all_clauses.update(
        [
            "PRE-LISTFOLDERS-01",
            "POST-LISTFOLDERS-01",
            "POST-LISTFOLDERS-02",
            "POST-LISTFOLDERS-03",
            "POST-LISTFOLDERS-04",
            "POST-LISTFOLDERS-05",
            "INV-LISTFOLDERS-01",
            "INV-LISTFOLDERS-02",
            "INV-LISTFOLDERS-03",
            "INV-LISTFOLDERS-04",
        ]
    )

    # Status clauses
    all_clauses.update(
        [
            "PRE-STATUS-01",
            "POST-STATUS-01",
            "POST-STATUS-02",
            "POST-STATUS-03",
            "POST-STATUS-04",
            "POST-STATUS-05",
            "INV-STATUS-01",
            "INV-STATUS-02",
            "INV-STATUS-03",
            "INV-STATUS-04",
        ]
    )

    # Global invariants
    all_clauses.update(
        [
            "INV-GLOBAL-01",
            "INV-GLOBAL-02",
            "INV-GLOBAL-03",
            "INV-GLOBAL-04",
            "INV-GLOBAL-05",
            "INV-GLOBAL-06",
            "INV-GLOBAL-07",
            "INV-GLOBAL-08",
            "INV-GLOBAL-09",
        ]
    )

    uncovered = all_clauses - covered_clauses

    return {
        "covered": sorted(covered_clauses),
        "uncovered": sorted(uncovered),
        "test_count": len(TEST_CASES),
        "coverage_pct": round(len(covered_clauses) / len(all_clauses) * 100, 1),
    }
