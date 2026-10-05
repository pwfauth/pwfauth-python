"""Official Python client for PWF Auth (https://pwfauth.com).

License-key activation, hardware-ID binding, encrypted sessions with a
server-driven kill switch, self-service device moves, accounts that run on license
keys, free trials, remote texts/slides, and OTA update checks.

    from pwfauth import PwfClient
    import os, sys

    client = PwfClient(os.environ["PWFAUTH_SECRET"])

    def on_session_ended(error_code, message):
        print(f"Session ended ({error_code}): {message}", file=sys.stderr)
        os._exit(1)

    client.on_session_ended = on_session_ended

    login = client.login("XXXXX-XXXXX-XXXXX-XXXXX")
    if not login.success:
        print(login.message, file=sys.stderr)
        sys.exit(1)

    client.start_heartbeat()   # keeps the session alive AND enforces the kill switch

The hardware ID is derived identically to the .NET and Node clients, so the same
machine counts as one device no matter which SDK an app uses.
"""

from .client import PwfClient
from .envelope import CryptoEnvelope
from .errors import (PwfCryptoError, PwfError, PwfErrorCodes, PwfHttpError,
                     PwfSecurityError, ends_session)
from .hardware_id import get_hardware_id, reset_hardware_id_cache
from .response import License, PwfResponse

from .client import __version__

__all__ = [
    "PwfClient",
    "PwfResponse",
    "License",
    "CryptoEnvelope",
    "PwfError",
    "PwfHttpError",
    "PwfCryptoError",
    "PwfSecurityError",
    "PwfErrorCodes",
    "ends_session",
    "get_hardware_id",
    "reset_hardware_id_cache",
    "__version__",
]
