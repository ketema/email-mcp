"""
IMAP Client Wrapper
===================

Read-only IMAP client implementing contract requirements.

CONSTITUTIONAL INVARIANTS:
- INV-GLOBAL-01: No delete capability
- INV-GLOBAL-02: No send capability
- INV-GLOBAL-03: No move capability
- INV-FETCH-01: Fetch does NOT mark messages as read
- INV-GLOBAL-05: No logging of message bodies or attachments
"""

from __future__ import annotations

import email
import email.utils
import re
from datetime import datetime
from email.header import decode_header
from typing import TYPE_CHECKING

from imapclient import IMAPClient

from contracts import (
    Attachment,
    AuthFailedError,
    ConnectionFailedError,
    ConnectionStatus,
    EmailAddress,
    EmailMessage,
    EmailProtocol,
    FolderInfo,
    FolderNotFoundError,
    InvalidRangeError,
    NotConnectedError,
    UidNotFoundError,
)

if TYPE_CHECKING:
    from src.email_mcp.credentials import Credentials


class EmailIMAPClient:
    """
    Read-only IMAP client.

    This class intentionally does NOT implement:
    - send/reply/forward (INV-GLOBAL-02)
    - delete/expunge (INV-GLOBAL-01)
    - move/copy (INV-GLOBAL-03)
    """

    def __init__(self) -> None:
        self._client: IMAPClient | None = None
        self._server: str = ""
        self._connected: bool = False
        self._start_time: datetime | None = None
        self._protocol: EmailProtocol = EmailProtocol.IMAP
        self._tls_version: str = ""
        self._cipher: str = ""

    @property
    def connected(self) -> bool:
        """Check if connected to server."""
        return self._connected and self._client is not None

    def connect(self, credentials: Credentials) -> None:
        """
        Connect and authenticate to IMAP server.

        PRE-STARTUP-04: Network connectivity available
        POST-STARTUP-02: IMAP connection established and authenticated
        """
        try:
            self._client = IMAPClient(
                credentials.server,
                port=credentials.port,
                ssl=credentials.use_ssl,
            )
            self._server = credentials.server
        except Exception as e:
            raise ConnectionFailedError(f"Failed to connect: {e}") from e

        try:
            self._client.login(credentials.username, credentials.password)
            self._connected = True
            self._start_time = datetime.now()
            # Extract TLS info (INV-GLOBAL-09: Transport Security)
            self._extract_tls_info()
        except Exception as e:
            self._client = None
            raise AuthFailedError(f"Authentication failed: {e}") from e

    def _extract_tls_info(self) -> None:
        """Extract TLS version and cipher from connection."""
        if self._client is None:
            return
        try:
            # Access the underlying socket's SSL info
            sock = getattr(self._client, "_imap", None)
            if sock and hasattr(sock, "ssl"):
                ssl_sock = sock.ssl()
                if ssl_sock:
                    self._tls_version = ssl_sock.version() or "Unknown"
                    cipher_info = ssl_sock.cipher()
                    if cipher_info:
                        self._cipher = cipher_info[0]  # Cipher name
                    else:
                        self._cipher = "Unknown"
        except Exception:
            # Fallback if we can't extract TLS info
            self._tls_version = "TLS"
            self._cipher = "Unknown"

    def disconnect(self) -> None:
        """Disconnect from server."""
        if self._client:
            try:
                self._client.logout()
            except Exception:
                pass
            finally:
                self._client = None
                self._connected = False

    def _require_connection(self) -> IMAPClient:
        """Ensure connected, raise NotConnectedError if not."""
        if not self._connected or self._client is None:
            raise NotConnectedError("Not connected to mail server")
        return self._client

    def get_status(self) -> ConnectionStatus:
        """
        Return current connection status.

        POST-STATUS-01: Returns ConnectionStatus
        POST-STATUS-02: connected reflects actual state
        INV-STATUS-04: Honest about connection state
        """
        uptime = 0
        if self._start_time and self._connected:
            uptime = int((datetime.now() - self._start_time).total_seconds())

        return ConnectionStatus(
            connected=self._connected,
            protocol=self._protocol,
            server=self._server,
            uptime_seconds=uptime,
            tls_version=self._tls_version,
            cipher=self._cipher,
        )

    def list_folders(self) -> list[FolderInfo]:
        """
        List all mailbox folders.

        POST-LISTFOLDERS-01: Returns list of FolderInfo
        POST-LISTFOLDERS-03: All accessible folders included
        INV-LISTFOLDERS-01: No server state modified
        """
        client = self._require_connection()

        folders = []
        for _flags, _delimiter, name in client.list_folders():
            # Get folder status
            try:
                status = client.folder_status(name, ["MESSAGES", "UNSEEN", "UIDVALIDITY"])
                folders.append(
                    FolderInfo(
                        name=name,
                        message_count=status.get(b"MESSAGES", 0),
                        unread_count=status.get(b"UNSEEN", 0),
                        uidvalidity=status.get(b"UIDVALIDITY", 0),
                    )
                )
            except Exception:
                # Skip folders we can't access
                continue

        return folders

    def fetch_messages(
        self,
        *,
        folder: str = "INBOX",
        date_after: str | None = None,
        date_before: str | None = None,
        limit: int,
        uid_gt: int | None = None,
    ) -> dict:
        """
        Fetch messages from folder with filtering.

        PRE-FETCH-02: folder is valid
        PRE-FETCH-05: date_after <= date_before if both provided
        PRE-FETCH-06: 1 <= limit <= 100

        POST-FETCH-01: Returns dict with messages, folder, uidvalidity, next_uid
        POST-FETCH-03: len(messages) <= limit
        POST-FETCH-07: Messages ordered by UID ascending

        INV-FETCH-01: Does NOT mark messages as read (uses BODY.PEEK)
        """
        client = self._require_connection()

        # Validate date range
        if date_after and date_before:
            after_dt = datetime.fromisoformat(date_after.replace("Z", "+00:00"))
            before_dt = datetime.fromisoformat(date_before.replace("Z", "+00:00"))
            if after_dt > before_dt:
                raise InvalidRangeError("date_after cannot be greater than date_before")

        # Select folder (readonly=True ensures INV-FETCH-01)
        try:
            select_info = client.select_folder(folder, readonly=True)
        except Exception as e:
            raise FolderNotFoundError(f"Folder not found: {folder}") from e

        uidvalidity = select_info.get(b"UIDVALIDITY", 0)
        next_uid = select_info.get(b"UIDNEXT", 0)

        # Build search criteria
        criteria = ["ALL"]

        if date_after:
            after_dt = datetime.fromisoformat(date_after.replace("Z", "+00:00"))
            criteria = ["SINCE", after_dt.date()]

        if date_before:
            before_dt = datetime.fromisoformat(date_before.replace("Z", "+00:00"))
            if len(criteria) > 1:
                criteria.extend(["BEFORE", before_dt.date()])
            else:
                criteria = ["BEFORE", before_dt.date()]

        if uid_gt is not None:
            # Search for UIDs greater than uid_gt
            criteria = ["UID", f"{uid_gt + 1}:*"]

        # Search for messages
        uids = client.search(criteria)

        # Filter by uid_gt if needed (double-check)
        if uid_gt is not None:
            uids = [uid for uid in uids if uid > uid_gt]

        # Sort by UID ascending (POST-FETCH-07)
        uids = sorted(uids)

        # Apply limit (POST-FETCH-03)
        uids = uids[:limit]

        # Fetch message data using BODY.PEEK to avoid marking as read (INV-FETCH-01)
        messages = []
        if uids:
            # Use BODY.PEEK instead of BODY to preserve \Seen flag
            fetch_data = client.fetch(uids, ["UID", "FLAGS", "INTERNALDATE", "BODY.PEEK[]"])

            for uid, data in fetch_data.items():
                msg = self._parse_message(uid, data)
                if msg:
                    # Apply date filters on parsed message
                    include = True
                    if date_after:
                        after_dt = datetime.fromisoformat(date_after.replace("Z", "+00:00"))
                        msg_dt = datetime.fromisoformat(msg.date.replace("Z", "+00:00"))
                        if msg_dt < after_dt:
                            include = False
                    if date_before and include:
                        before_dt = datetime.fromisoformat(date_before.replace("Z", "+00:00"))
                        msg_dt = datetime.fromisoformat(msg.date.replace("Z", "+00:00"))
                        if msg_dt > before_dt:
                            include = False

                    if include:
                        messages.append(msg)

        # Ensure ordered by UID (POST-FETCH-07)
        messages.sort(key=lambda m: m.uid)

        # Re-apply limit after filtering
        messages = messages[:limit]

        return {
            "messages": messages,
            "folder": folder,
            "uidvalidity": uidvalidity,
            "next_uid": next_uid,
        }

    def mark_read(self, *, folder: str, uids: list[int]) -> dict:
        """
        Mark messages as read (set \\Seen flag).

        PRE-MARKREAD-03: uids is non-empty list
        PRE-MARKREAD-04: All UIDs exist in folder

        POST-MARKREAD-01: Returns dict with marked, folder
        POST-MARKREAD-04: All messages now have \\Seen flag

        INV-MARKREAD-01: ONLY \\Seen flag modified
        INV-MARKREAD-03: Message count unchanged (no delete)
        INV-MARKREAD-04: Idempotent
        """
        client = self._require_connection()

        # Select folder (not readonly - we need to modify flags)
        try:
            client.select_folder(folder)
        except Exception as e:
            raise FolderNotFoundError(f"Folder not found: {folder}") from e

        # Verify UIDs exist
        existing_uids = client.search(["UID", f"{min(uids)}:{max(uids)}"])
        missing = set(uids) - set(existing_uids)
        if missing:
            raise UidNotFoundError(f"UIDs not found: {missing}")

        # Add \\Seen flag (INV-MARKREAD-01: only this flag)
        client.add_flags(uids, [b"\\Seen"])

        return {
            "marked": uids,
            "folder": folder,
        }

    def _parse_message(self, uid: int, data: dict) -> EmailMessage | None:
        """Parse raw IMAP data into EmailMessage."""
        try:
            raw = data.get(b"BODY[]") or data.get(b"BODY.PEEK[]")
            if not raw:
                return None

            msg = email.message_from_bytes(raw)
            flags = [f.decode() if isinstance(f, bytes) else f for f in data.get(b"FLAGS", [])]
            internal_date = data.get(b"INTERNALDATE")

            # Parse addresses
            from_addr = self._parse_address(msg.get("From", ""))
            to_addrs = self._parse_address_list(msg.get("To", ""))
            cc_addrs = self._parse_address_list(msg.get("Cc", ""))
            bcc_addrs = self._parse_address_list(msg.get("Bcc", ""))

            # Parse date
            date_str = msg.get("Date", "")
            try:
                parsed_date = email.utils.parsedate_to_datetime(date_str)
                date_iso = parsed_date.isoformat()
            except Exception:
                date_iso = datetime.now().isoformat()

            # Internal date
            if internal_date:
                internal_iso = internal_date.isoformat()
            else:
                internal_iso = date_iso

            # Parse body and attachments
            body_plain = None
            body_html = None
            attachments = []

            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disp = str(part.get("Content-Disposition", ""))

                    if "attachment" in content_disp:
                        attachments.append(self._parse_attachment(part))
                    elif content_type == "text/plain" and body_plain is None:
                        body_plain = self._decode_payload(part)
                    elif content_type == "text/html" and body_html is None:
                        body_html = self._decode_payload(part)
            else:
                content_type = msg.get_content_type()
                if content_type == "text/plain":
                    body_plain = self._decode_payload(msg)
                elif content_type == "text/html":
                    body_html = self._decode_payload(msg)

            # Parse threading info
            message_id = msg.get("Message-ID", f"<{uid}@unknown>")
            in_reply_to = msg.get("In-Reply-To")
            references_raw = msg.get("References", "")
            references = references_raw.split() if references_raw else []

            # Derive thread_id
            thread_id = self._derive_thread_id(
                message_id, in_reply_to, references, msg.get("Subject", "")
            )

            return EmailMessage(
                uid=uid,
                message_id=message_id,
                thread_id=thread_id,
                from_addr=from_addr,
                to_addrs=to_addrs,
                cc_addrs=cc_addrs,
                bcc_addrs=bcc_addrs,
                subject=self._decode_header(msg.get("Subject", "")),
                date=date_iso,
                internal_date=internal_iso,
                body_plain=body_plain,
                body_html=body_html,
                attachments=attachments,
                flags=flags,
                in_reply_to=in_reply_to,
                references=references,
            )
        except Exception:
            return None

    def _parse_address(self, addr_str: str) -> EmailAddress:
        """Parse a single email address."""
        if not addr_str:
            return EmailAddress(name=None, address="")

        name, address = email.utils.parseaddr(addr_str)
        return EmailAddress(
            name=self._decode_header(name) if name else None,
            address=address,
        )

    def _parse_address_list(self, addr_str: str) -> list[EmailAddress]:
        """Parse a comma-separated list of addresses."""
        if not addr_str:
            return []

        addresses = []
        for name, address in email.utils.getaddresses([addr_str]):
            addresses.append(
                EmailAddress(
                    name=self._decode_header(name) if name else None,
                    address=address,
                )
            )
        return addresses

    def _decode_header(self, header: str) -> str:
        """Decode RFC 2047 encoded header."""
        if not header:
            return ""

        decoded_parts = []
        for part, charset in decode_header(header):
            if isinstance(part, bytes):
                decoded_parts.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                decoded_parts.append(part)
        return " ".join(decoded_parts)

    def _decode_payload(self, part: email.message.Message) -> str:
        """Decode message payload."""
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""

        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")

    def _parse_attachment(self, part: email.message.Message) -> Attachment:
        """Parse attachment from message part."""
        import base64

        filename = part.get_filename() or "unnamed"
        filename = self._decode_header(filename)
        mime_type = part.get_content_type()
        payload = part.get_payload(decode=True) or b""

        return Attachment(
            filename=filename,
            mime_type=mime_type,
            size_bytes=len(payload),
            content_base64=base64.b64encode(payload).decode("ascii"),
        )

    def _derive_thread_id(
        self,
        message_id: str,
        in_reply_to: str | None,
        references: list[str],
        subject: str,
    ) -> str:
        """
        Derive thread_id per Threading Contract.

        1. First Message-ID in References header chain
        2. FALLBACK: In-Reply-To header value
        3. FALLBACK: Subject normalization
        """
        # Priority 1: First reference
        if references:
            return references[0]

        # Priority 2: In-Reply-To
        if in_reply_to:
            return in_reply_to

        # Priority 3: Normalized subject
        normalized = re.sub(r"^(re|fwd|fw):\s*", "", subject, flags=re.IGNORECASE).strip()
        return f"<thread:{normalized}>"
