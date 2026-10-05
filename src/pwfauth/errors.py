"""Exception types and the server's error-code vocabulary."""

from __future__ import annotations


class PwfError(Exception):
    """Base class for every error this library raises."""


class PwfCryptoError(PwfError):
    """The encrypted envelope could not be built, verified, or decrypted.

    Usually the wrong app secret or a tampered payload. A wrong machine clock is
    repaired automatically (see ``auto_correct_clock``).
    """


class PwfHttpError(PwfError):
    """No usable reply: the server could not be reached, or it answered with a
    failing status or a body that was not the API's JSON.

    ``status`` is the HTTP status (0 when there was no reply at all). ``snippet``
    carries the first 200 characters of what actually came back, which is what turns
    "unexpected token <" into "your proxy returned an HTML error page".
    """

    def __init__(self, message: str, status: int = 0, snippet: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.snippet = snippet


class PwfSecurityError(PwfError):
    """An encrypted endpoint answered with an UNENCRYPTED "success".

    The license server encrypts every reply of these endpoints once it has accepted
    the app secret; only refusals travel as plain JSON. A plain success therefore did
    not come from PWF Auth -- a proxy, a hosts-file redirect or a fake server sent it.
    Never unlock the application on it.
    """


class PwfErrorCodes:
    """Error codes the API returns in ``error_code``, plus the two this client raises.

    :func:`ends_session` says which ones mean the licence is finished on this
    machine; everything else is worth retrying or reporting.
    """

    # The licence or account state -- the session is over.
    BANNED = "BANNED"
    PAUSED = "PAUSED"
    EXPIRED = "EXPIRED"
    HWID_RESET = "HWID_RESET"            # an admin cleared the binding, or another PC took it
    MAINTENANCE = "MAINTENANCE"
    SESSION_EXPIRED = "SESSION_EXPIRED"  # the session no longer exists on the server
    SESSION_MISMATCH = "SESSION_MISMATCH"
    SESSION_REVOKED = "SESSION_REVOKED"  # the key or account behind it was deleted

    # Sign-in refusals.
    MISSING_FIELDS = "MISSING_FIELDS"
    INVALID_KEY = "INVALID_KEY"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    HWID_MISMATCH = "HWID_MISMATCH"      # bound to another PC: reset_hardware_id() moves it
    DEVICE_LIMIT = "DEVICE_LIMIT"        # multi-device key already on its maximum of PCs
    OPEN_ACCESS_LIMIT = "OPEN_ACCESS_LIMIT"
    KEY_REDEEMED = "KEY_REDEEMED"        # the key was added to an account: sign in with that

    # Free trials.
    TRIAL_DISABLED = "TRIAL_DISABLED"
    TRIAL_USED = "TRIAL_USED"
    TRIAL_LIMIT = "TRIAL_LIMIT"

    # Self-service hardware reset (reset_hardware_id).
    KEY_NOT_ACTIVE = "KEY_NOT_ACTIVE"
    NO_HWID = "NO_HWID"
    RATE_LIMITED = "RATE_LIMITED"        # also: the cooldown since the last reset
    SELF_RESET_DISABLED = "SELF_RESET_DISABLED"

    # Accounts that run on license keys.
    KEY_REQUIRED = "KEY_REQUIRED"        # the app wants a key at sign-up
    KEY_ALREADY_USED = "KEY_ALREADY_USED"
    KEY_IN_USE = "KEY_IN_USE"
    ALREADY_LIFETIME = "ALREADY_LIFETIME"
    USERNAME_EXISTS = "USERNAME_EXISTS"

    # The server could not verify the request (wrong secret, or a clock far off).
    CRYPTO_ERROR = "CRYPTO_ERROR"

    # Raised by this client, never sent by the server.
    NETWORK_LOST = "NETWORK_LOST"        # the heartbeat ran out of answered beats
    CLOCK_SKEW = "CLOCK_SKEW"            # ...because the server kept rejecting this PC's clock

    # Kept from 1.0.x for code that compares against them. The server never sends these.
    KEY_BANNED = "KEY_BANNED"
    KEY_PAUSED = "KEY_PAUSED"
    KEY_EXPIRED = "KEY_EXPIRED"
    KEY_REVOKED = "KEY_REVOKED"
    KEY_NOT_FOUND = "KEY_NOT_FOUND"
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    APP_DISABLED = "APP_DISABLED"
    SERVER_ERROR = "SERVER_ERROR"
    INVALID_REQUEST = "INVALID_REQUEST"

    SESSION_ENDING = frozenset({
        BANNED, PAUSED, EXPIRED, HWID_RESET, MAINTENANCE,
        SESSION_EXPIRED, SESSION_MISMATCH, SESSION_REVOKED,
        NETWORK_LOST, CLOCK_SKEW,
        # 1.0.x names, harmless to keep.
        KEY_BANNED, KEY_PAUSED, KEY_EXPIRED, KEY_REVOKED, KEY_NOT_FOUND,
        HWID_MISMATCH, SESSION_NOT_FOUND, APP_DISABLED,
    })


def ends_session(error_code: str | None) -> bool:
    """True when this code means the licence is finished on this machine.

    Use it to decide whether to sign the user out. An unknown code returns False on
    purpose: a code this library has not heard of is far more likely to be a new
    transient condition than a new way of being banned, and locking users out of a
    paid app on a guess is the worse failure.
    """
    return bool(error_code) and error_code in PwfErrorCodes.SESSION_ENDING
