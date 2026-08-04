"""The PWF Auth client.

Mirrors the .NET and Node clients: same envelope, same endpoints, same error codes,
same hardware-ID derivation. Zero dependencies beyond ``cryptography`` -- HTTP goes
through :mod:`urllib.request` rather than pulling ``requests`` and its four
transitive dependencies into every app that installs this.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from typing import Any, Callable

from .envelope import CryptoEnvelope
from .errors import PwfError, PwfHttpError, ends_session
from .hardware_id import get_hardware_id
from .response import PwfResponse

__all__ = ["PwfClient", "__version__"]

__version__ = "1.0.1"

_DEFAULT_BASE_URL = "https://pwfauth.com"

# urllib sends "Python-urllib/3.x" unless told otherwise, and Cloudflare — which
# fronts pwfauth.com — rejects that outright with a 403 and error code 1010, before
# the request ever reaches the app. Identifying ourselves properly is what makes the
# library usable at all against the live server, not a nicety.
_DEFAULT_USER_AGENT = f"pwfauth-python/{__version__} (+https://pwfauth.com)"


class PwfClient:
    """A licence client for one application.

    ``on_session_ended`` is the callback that matters: assign a function taking
    ``(error_code, message)`` and it fires the moment the licence stops being valid
    on this machine -- a ban, pause, expiry, HWID reset, revoke, maintenance window,
    or a server that has gone unreachable past the failure budget. Logging alone
    leaves the licence unenforceable; stop the app there.
    """

    def __init__(
        self,
        app_secret: str,
        *,
        base_url: str = _DEFAULT_BASE_URL,
        heartbeat_seconds: int = 60,
        max_heartbeat_failures: int = 3,
        timeout: float = 15.0,
        hardware_id: str | None = None,
        user_agent: str = _DEFAULT_USER_AGENT,
    ) -> None:
        if not app_secret or not isinstance(app_secret, str):
            raise TypeError("app_secret is required.")

        self.app_secret = app_secret
        self.user_agent = user_agent
        self.base_url = base_url.rstrip("/")
        self.heartbeat_seconds = heartbeat_seconds
        self.max_heartbeat_failures = max_heartbeat_failures
        self.timeout = timeout
        self.hardware_id = hardware_id or get_hardware_id()

        self.on_session_ended: Callable[[str | None, str | None], None] | None = None

        self._crypto = CryptoEnvelope(app_secret)
        self._session_id: str | None = None
        self._license_key: str | None = None
        self._timer: threading.Timer | None = None
        self._lock = threading.Lock()
        self._failures = 0

    # ── state ────────────────────────────────────────────────────────────────

    @property
    def is_signed_in(self) -> bool:
        return self._session_id is not None

    @property
    def session_id(self) -> str | None:
        return self._session_id

    # ── licence lifecycle ────────────────────────────────────────────────────

    def login(self, license_key: str) -> PwfResponse:
        """Activate a licence key on this machine and open a session."""
        if not license_key or not isinstance(license_key, str):
            raise TypeError("license_key is required.")
        res = self.post_envelope("/api/auth/login.php", {
            "license_key": license_key,
            "hwid": self.hardware_id,
        })
        if res.success:
            self._session_id = res.data.get("session_id")
            self._license_key = license_key
            self._failures = 0
        return res

    def check_key(self, license_key: str) -> PwfResponse:
        """Read a key's state WITHOUT opening a session, so no device seat is used."""
        if not license_key or not isinstance(license_key, str):
            raise TypeError("license_key is required.")
        return self.post_envelope("/api/auth/check-key.php", {
            "license_key": license_key,
            "hwid": self.hardware_id,
        })

    def heartbeat(self) -> PwfResponse:
        """Send one heartbeat. Raises if called before :meth:`login`."""
        if not self._session_id:
            raise PwfError("Not signed in — call login() before heartbeat().")
        return self.post_envelope("/api/auth/heartbeat.php", {
            "session_id": self._session_id,
            "license_key": self._license_key,
            "hwid": self.hardware_id,
        })

    def logout(self) -> PwfResponse:
        """Close the session and free the device seat."""
        if not self._session_id:
            raise PwfError("Not signed in.")
        try:
            return self.post_envelope("/api/auth/logout.php", {
                "session_id": self._session_id,
                "license_key": self._license_key,
            })
        finally:
            self.stop_heartbeat()
            self._session_id = None
            self._license_key = None

    # ── heartbeat loop ───────────────────────────────────────────────────────

    def start_heartbeat(self) -> None:
        """Begin the background heartbeat.

        This is what turns a one-time check into a live session and enforces the
        kill switch. A daemon timer, so it never keeps the interpreter alive.
        """
        if not self._session_id:
            raise PwfError("Not signed in — call login() before start_heartbeat().")
        self.stop_heartbeat()
        self._schedule()

    def stop_heartbeat(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

    def _schedule(self) -> None:
        with self._lock:
            self._timer = threading.Timer(self.heartbeat_seconds, self._tick)
            self._timer.daemon = True
            self._timer.start()

    def _tick(self) -> None:
        if not self._session_id:
            return
        try:
            res = self.heartbeat()
        except Exception:
            # Unreachable server. Tolerate a few in a row — a laptop lid, a train
            # tunnel, a Wi-Fi handover — then treat it as the session ending, so a
            # pulled network cable cannot be used to outrun a revoke.
            self._failures += 1
            if self._failures >= self.max_heartbeat_failures:
                self._end_session("NETWORK_LOST", "The license server is unreachable.")
                return
            self._schedule()
            return

        self._failures = 0
        if not res.success and ends_session(res.error_code):
            self._end_session(res.error_code, res.message)
            return
        # Any other failure is transient (rate limit, a 500) — keep the loop alive.
        self._schedule()

    def _end_session(self, error_code: str | None, message: str | None) -> None:
        self.stop_heartbeat()
        self._session_id = None
        self._license_key = None
        if self.on_session_ended:
            self.on_session_ended(error_code, message)

    # ── app content and updates ──────────────────────────────────────────────

    def get_app_info(self) -> PwfResponse:
        return self.get_envelope("/api/app/info.php")

    def get_texts(self, license_key: str | None = None) -> PwfResponse:
        return self.get_envelope("/api/app/text.php", bearer_license_key=license_key)

    def get_slides(self) -> PwfResponse:
        return self.post_envelope("/api/app/slides.php", {})

    def check_update(self, current_version: str) -> PwfResponse:
        if not current_version or not isinstance(current_version, str):
            raise TypeError("current_version is required.")
        return self.post_envelope("/api/update/check.php", {"version": current_version})

    def track_social_click(self, platform: str) -> PwfResponse:
        if not platform or not isinstance(platform, str):
            raise TypeError("platform is required.")
        return self.post_envelope("/api/app/social-click.php", {"platform": platform})

    # ── plain-JSON endpoints (no envelope) ───────────────────────────────────

    def create_trial(self) -> PwfResponse:
        return self.post_plain("/api/auth/trial.php", {"hwid": self.hardware_id})

    def request_hardware_reset(self, license_key: str, reason: str = "") -> PwfResponse:
        if not license_key or not isinstance(license_key, str):
            raise TypeError("license_key is required.")
        return self.post_plain("/api/auth/request-hwid-reset.php", {
            "license_key": license_key,
            "hwid": self.hardware_id,
            "reason": reason,
        })

    def register_account(self, username: str, password: str, license_key: str) -> PwfResponse:
        return self.post_plain("/api/auth/account-register.php", {
            "username": username,
            "password": password,
            "license_key": license_key,
            "hwid": self.hardware_id,
        })

    def account_login(self, username: str, password: str) -> PwfResponse:
        res = self.post_plain("/api/auth/account-login.php", {
            "username": username,
            "password": password,
            "hwid": self.hardware_id,
        })
        if res.success:
            self._session_id = res.data.get("session_id")
            self._license_key = (res.license.license_key if res.license else None)
            self._failures = 0
        return res

    def change_account_password(self, username: str, old_password: str,
                                new_password: str) -> PwfResponse:
        return self.post_plain("/api/auth/change-password.php", {
            "username": username,
            "old_password": old_password,
            "new_password": new_password,
        })

    # ── transports ───────────────────────────────────────────────────────────

    def post_envelope(self, path: str, body: Any = None) -> PwfResponse:
        """POST an encrypted envelope and decrypt the reply."""
        return self._send(path, method="POST",
                          headers={"Content-Type": "application/json",
                                   "X-App-Secret": self.app_secret},
                          data=self._crypto.encrypt(json.dumps(body or {})).encode("utf-8"))

    def get_envelope(self, path: str, bearer_license_key: str | None = None) -> PwfResponse:
        headers = {"X-App-Secret": self.app_secret}
        if bearer_license_key:
            headers["Authorization"] = "Bearer " + bearer_license_key
        return self._send(path, method="GET", headers=headers, data=None)

    def post_plain(self, path: str, body: Any = None) -> PwfResponse:
        """POST unencrypted JSON, for the endpoints that do not use the envelope."""
        return self._send(path, method="POST",
                          headers={"Content-Type": "application/json",
                                   "X-App-Secret": self.app_secret},
                          data=json.dumps(body or {}).encode("utf-8"))

    def _send(self, path: str, *, method: str, headers: dict, data: bytes | None) -> PwfResponse:
        req = urllib.request.Request(self.base_url + path, data=data, method=method)
        for k, v in headers.items():
            req.add_header(k, v)
        # Set last and unconditionally: without it urllib's default identifies the
        # caller as Python-urllib, which Cloudflare blocks with a 403 (code 1010).
        if self.user_agent:
            req.add_header("User-Agent", self.user_agent)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            # A 4xx still carries a JSON error envelope worth reading — Cloudflare
            # eats 5xx bodies, which is why the server uses 4xx for API errors.
            status = e.code
            raw = e.read().decode("utf-8", errors="replace")
        except Exception as cause:
            raise PwfHttpError(f"Could not reach the license server: {cause}") from cause

        if CryptoEnvelope.looks_like_envelope(raw):
            raw = self._crypto.decrypt(raw)

        try:
            return PwfResponse.parse(raw)
        except PwfError:
            # Not JSON: an HTML error page from a proxy is the usual cause, so hand
            # back a snippet instead of "unexpected token <".
            raise PwfHttpError(
                f"The license server returned a non-JSON body (HTTP {status}).",
                status=status, snippet=raw[:200])
