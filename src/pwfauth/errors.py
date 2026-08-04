"""Exception types and the server's error-code vocabulary."""

from __future__ import annotations


class PwfError(Exception):
    """Base class for every error this library raises."""


class PwfCryptoError(PwfError):
    """The encrypted envelope could not be built, verified, or decrypted.

    Usually one of: the wrong app secret, a tampered payload, or a machine clock
    far enough out of step that the timestamp fell outside the replay window.
    """


class PwfHttpError(PwfError):
    """The server answered with a non-success status, or a body that was not JSON.

    ``snippet`` carries the first 200 characters of what actually came back, which
    is what turns "unexpected token <" into "your proxy returned an HTML error page".
    """

    def __init__(self, message: str, status: int = 0, snippet: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.snippet = snippet


class PwfErrorCodes:
    """Error codes the API returns in ``error_code``.

    Grouped by what the client should DO, not by what went wrong. Anything in
    :data:`SESSION_ENDING` means the licence is no longer valid on this machine and
    the app must stop; everything else is worth retrying or reporting.
    """

    # Licence state — the session is over.
    KEY_BANNED = "KEY_BANNED"
    KEY_PAUSED = "KEY_PAUSED"
    KEY_EXPIRED = "KEY_EXPIRED"
    KEY_REVOKED = "KEY_REVOKED"
    KEY_NOT_FOUND = "KEY_NOT_FOUND"
    HWID_MISMATCH = "HWID_MISMATCH"
    HWID_RESET = "HWID_RESET"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    MAINTENANCE = "MAINTENANCE"
    APP_DISABLED = "APP_DISABLED"

    # Client-side, raised by this library rather than the server.
    NETWORK_LOST = "NETWORK_LOST"

    # Transient / informational — keep going.
    RATE_LIMITED = "RATE_LIMITED"
    SERVER_ERROR = "SERVER_ERROR"
    INVALID_REQUEST = "INVALID_REQUEST"

    SESSION_ENDING = frozenset({
        KEY_BANNED, KEY_PAUSED, KEY_EXPIRED, KEY_REVOKED, KEY_NOT_FOUND,
        HWID_MISMATCH, HWID_RESET, SESSION_EXPIRED, SESSION_NOT_FOUND,
        MAINTENANCE, APP_DISABLED, NETWORK_LOST,
    })


def ends_session(error_code: str | None) -> bool:
    """True when this code means the licence is finished on this machine.

    Use it to decide whether to sign the user out. An unknown code returns False on
    purpose: a code this library has not heard of is far more likely to be a new
    transient condition than a new way of being banned, and locking users out of a
    paid app on a guess is the worse failure.
    """
    return bool(error_code) and error_code in PwfErrorCodes.SESSION_ENDING
