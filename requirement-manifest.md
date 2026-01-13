# REQ-2026-002: Email Protocol MCP Server

## 1. Intent Traceability

- **Source Prose**:

> “I want to build a tool that processes my email in insightful actions. A dynamic task list to reduce the cognitive overhead of sorting through spam. This tool will really be a tool for an AI agent. It could be MCP but whatever gets the job done. The agent should be able to authenticate and check my email via any email protocol and at minimum POP and IMAP. Once it has access to my email I want it to look for specific mentions for actions I am being called to take, be able to distinguish between threads I need to respond to and those I don’t. To be able to alert on company training requirements or administrative tasks that need my attention. The system should be quiet by default, only alerting on error unless configured otherwise.”
- **Decomposition**: This requirement was split into TWO systems during interrogation:
1. **System 1 (This Document)**: Email Protocol MCP Server — dumb pipe transport layer
1. **System 2 (Separate Manifest)**: Email Intelligence Agent — classification and task extraction
- **Ambiguity Score**: 1 ✓ (Ready for implementation)

-----

## 2. The Actor Matrix

|Actor                   |Permission Level                         |Prohibited Actions                     |
|:-----------------------|:----------------------------------------|:--------------------------------------|
|AI Agent (MCP caller)   |Read, Mark-as-Read, List Folders         |Delete, Move, Send, Credential Access  |
|Human (credential owner)|Biometric approval at process start      |Direct MCP tool calls                  |
|biosecret               |Credential retrieval on biometric success|Credential persistence outside keychain|
|External email clients  |Full mailbox access (outside scope)      |N/A                                    |

-----

## 3. The State Transition (CABDD Focus)

### Startup Transition

- **Initial State ($S_0$)**: MCP process not running. Credentials in macOS Keychain.
- **Transformation**: Process start → biosecret invocation → biometric auth → credential load → IMAP/POP3 connect
- **Terminal State ($S_1$)**: MCP process running, connected, credentials in memory only.

### Fetch Transition

- **Initial State ($S_0$)**: Folder F contains N messages, M unread, max UID = U
- **Transformation**: `email_fetch(folder=F, limit=L, uid_gt=X)`
- **Terminal State ($S_1$)**: Folder F unchanged (N messages, M unread). Agent has message data.

### Mark Read Transition

- **Initial State ($S_0$)**: Messages with UIDs [A, B, C] have flags F_a, F_b, F_c
- **Transformation**: `email_mark_read(folder=F, uids=[A, B, C])`
- **Terminal State ($S_1$)**: Messages have flags F_a ∪ {\Seen}, F_b ∪ {\Seen}, F_c ∪ {\Seen}

-----

## 4. Hard Invariants (The “Never” List)

|ID           |Category              |Invariant                                                                |
|-------------|----------------------|-------------------------------------------------------------------------|
|INV-GLOBAL-01|Message Integrity     |This MCP server MUST NOT delete messages                                 |
|INV-GLOBAL-02|Capability Restriction|MCP server CANNOT send, reply, or forward email                          |
|INV-GLOBAL-03|Capability Restriction|MCP server CANNOT move messages between folders                          |
|INV-GLOBAL-04|Credential Security   |Credentials retrieved via biosecret, held in memory only, never persisted|
|INV-GLOBAL-05|Data Security         |Email bodies and attachments MUST NOT appear in logs                     |
|INV-GLOBAL-06|Explicit Mutation     |Fetch does not mutate state; mark-as-read requires explicit call         |
|INV-GLOBAL-07|Process Lifecycle     |Process termination clears all credentials from memory                   |
|INV-GLOBAL-08|Connection Model      |One mail server connection per process, no pooling                       |

-----

## 5. High-Entropy Zones (Adjudicated)

These ambiguities were identified during interrogation and resolved:

|Zone                |Question                       |Resolution                                                                 |
|--------------------|-------------------------------|---------------------------------------------------------------------------|
|Credential Ghost    |Auth failure handling?         |Structured JSON error. Agent handles retry. Human provides new credentials.|
|Protocol Ambiguity  |Read-only or mutate?           |Can mark as read. Cannot delete or move.                                   |
|Thread Identity     |How to group threads?          |References → In-Reply-To → Subject normalization                           |
|Silence Paradox     |What breaks silence?           |N/A — this is transport layer; intelligence layer handles alerts           |
|Message ID          |How to track state?            |Agent uses UID + folder + UIDValidity, or Message-ID header                |
|Fetch Scope         |All messages?                  |Date range + quantity + uid_gt filter. Agent tracks what it’s seen.        |
|Connection Lifecycle|Per-call or persistent?        |stdio transport; connection persists for process lifetime                  |
|Credential Flow     |Per-call credentials?          |biosecret at startup. Memory only. Crash = re-auth via biometric.          |
|External Mutation   |Can we guarantee message count?|No. External clients can delete. We guarantee WE don’t delete.             |

-----

## 6. Tool Interface Summary

|Tool                |Purpose                       |Mutates State?  |
|--------------------|------------------------------|----------------|
|`email_fetch`       |Retrieve messages with filters|NO              |
|`email_mark_read`   |Set \Seen flag on messages    |YES (flags only)|
|`email_list_folders`|List available folders        |NO              |
|`email_status`      |Health check                  |NO              |

-----

## 7. Completion Promise (The Exit Condition)

> “The Ralph loop is complete when the Constitutional Auditor verifies:
> 
> 1. `email_fetch` returns messages matching filters WITHOUT marking them read
> 1. `email_mark_read` sets \Seen flag on specified UIDs ONLY
> 1. `email_list_folders` returns all folders with accurate counts
> 1. `email_status` honestly reports connection state
> 1. Startup retrieves credentials via biosecret and holds in memory only
> 1. ALL INV-GLOBAL invariants have adversarial tests that FAIL if violated
> 1. NO credential or email body appears in ANY log output
> 1. ALL tests trace to specific contract clause IDs (CL12-E compliance)”

-----

## 8. Contract Authority

**Authoritative Source**: `contracts/email_protocol_contract.py`

This manifest is the REQUIREMENTS document.  
The contract file is the SPECIFICATION derived from requirements.  
Tests are the VERIFICATION of specification.  
Implementation is the REALIZATION of specification.

```
REQUIREMENT_MANIFEST.md (this file)
        ↓
contracts/email_protocol_contract.py
        ↓
tests/test_email_protocol_contract.py
        ↓
src/email_mcp_server.py
```

Each layer traces to the one above. No orphaned code. No undeclared behavior.

-----

## 9. Related Documents

- **System 2 Manifest**: `REQ-2026-003_email_intelligence_agent.md` (not yet created)
- **Constitutional Framework**: AGENTS.md, CLAUDE.md
- **Skills**: theater-detection, constitutional-audit, cl12-examples

-----

## 10. Revision History

|Date      |Author                |Change                                  |
|----------|----------------------|----------------------------------------|
|2026-01-13|Ketema Harris + Claude|Initial manifest from cl-req:interrogate|