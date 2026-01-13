"""
Credentials Management
======================

Abstraction for credential retrieval. In production, this would use biosecret.
For testing, this can be mocked.

INV-STARTUP-01: Credentials held in memory only, never written to disk.
INV-GLOBAL-04: Credentials retrieved at startup, held in memory only.
"""

import json
import subprocess
from dataclasses import dataclass

from contracts import (
    BiosecretDeniedError,
    BiosecretNotFoundError,
)


@dataclass(frozen=True)
class Credentials:
    """Email credentials held in memory only."""

    username: str
    password: str
    server: str
    port: int = 993
    use_ssl: bool = True


def retrieve_credentials(account_id: str) -> Credentials:
    """
    Retrieve credentials via biosecret CLI.

    PRE: biosecret CLI is available in PATH
    PRE: User has stored credentials under key "email-mcp/{account_id}"

    POST: Returns Credentials on success

    ERRORS:
    - BiosecretDeniedError: User cancelled biometric prompt
    - BiosecretNotFoundError: No credentials under expected key
    """
    try:
        result = subprocess.run(
            ["biosecret", "get", f"email-mcp/{account_id}"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            stderr = result.stderr.lower() if result.stderr else ""
            if "cancel" in stderr or "denied" in stderr:
                raise BiosecretDeniedError("User cancelled biometric authentication")
            raise BiosecretNotFoundError(f"No credentials found for {account_id}")

        data = json.loads(result.stdout)
        return Credentials(
            username=data["username"],
            password=data["password"],
            server=data.get("server", "imap.gmail.com"),
            port=data.get("port", 993),
            use_ssl=data.get("use_ssl", True),
        )
    except subprocess.TimeoutExpired as e:
        raise BiosecretDeniedError("Biometric authentication timed out") from e
    except json.JSONDecodeError as e:
        raise BiosecretNotFoundError("Invalid credential format") from e
    except FileNotFoundError as e:
        raise BiosecretNotFoundError("biosecret CLI not found in PATH") from e
