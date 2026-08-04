"""The parsed reply from the licence server."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .errors import PwfError


def _to_datetime(value) -> datetime | None:
    """Parse the server's timestamps, returning None for anything unusable.

    Lifetime keys send ``expires_at: null``. Returning None rather than raising is
    deliberate -- treating that null as a date is the single most common integration
    bug against this API.
    """
    if not value or not isinstance(value, str):
        return None
    text = value.strip().replace(" ", "T")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class License:
    """The licence block from a login reply."""

    license_key: str | None = None
    key_type: str | None = None
    duration: int | None = None
    hwid: str | None = None
    activated_at: datetime | None = None
    expires_at: datetime | None = None
    days_remaining: int | None = None
    status: str | None = None

    @property
    def is_lifetime(self) -> bool:
        """True when the key never expires.

        The library answers this so callers never have to special-case a null date.
        """
        return self.expires_at is None


@dataclass(frozen=True)
class PwfResponse:
    """A licence-server reply, with the raw body kept reachable as fields grow."""

    data: dict = field(default_factory=dict)
    raw_json: str = ""

    @staticmethod
    def parse(body: str) -> "PwfResponse":
        try:
            data = json.loads(body)
        except Exception as cause:
            raise PwfError(
                "The license server returned a body that is not valid JSON.") from cause
        if not isinstance(data, dict):
            raise PwfError("The license server returned a body that is not a JSON object.")
        return PwfResponse(data=data, raw_json=body)

    @property
    def success(self) -> bool:
        """True when the API reported success."""
        return self.data.get("success") is True

    @property
    def error_code(self) -> str | None:
        """Machine-readable failure reason. Compare against :class:`PwfErrorCodes`."""
        code = self.data.get("error_code")
        return code if isinstance(code, str) else None

    @property
    def message(self) -> str | None:
        """Human-readable message, safe to show the end user."""
        msg = self.data.get("message")
        return msg if isinstance(msg, str) else None

    @property
    def license(self) -> License | None:
        """The licence block, or None when the reply carries no ``user`` object."""
        u = self.data.get("user")
        if not isinstance(u, dict):
            return None
        days = u.get("days_remaining")
        return License(
            license_key=u.get("license_key"),
            key_type=u.get("key_type"),
            duration=u.get("duration"),
            hwid=u.get("hwid"),
            activated_at=_to_datetime(u.get("activated_at")),
            expires_at=_to_datetime(u.get("expires_at")),
            days_remaining=days if isinstance(days, int) else None,
            status=u.get("status"),
        )

    @property
    def features(self) -> dict:
        """Per-key feature flags. Empty dict when absent."""
        f = self.data.get("features")
        return f if isinstance(f, dict) else {}

    def get_boolean(self, key: str, default: bool = False) -> bool:
        """Read a feature flag, tolerating the 1/0/"true" forms the panel can store."""
        if key not in self.features:
            return default
        v = self.features[key]
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return v != 0
        if isinstance(v, str):
            return v.strip().lower() in ("1", "true", "yes", "on")
        return default
