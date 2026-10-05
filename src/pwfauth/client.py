"""The PWF Auth client.

Mirrors the .NET client (NuGet ``PWFAuth`` 1.3.0): same envelope, same endpoints,
same error codes, same hardware-ID derivation, same heartbeat rules. Zero
dependencies beyond ``cryptography`` -- HTTP goes through :mod:`urllib.request`
rather than pulling ``requests`` and its four transitive dependencies into every
app that installs this.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
import warnings
from typing import Any, Callable
from urllib.parse import urlparse

from .envelope import CryptoEnvelope
from .errors import (PwfCryptoError, PwfError, PwfErrorCodes, PwfHttpError,
                     PwfSecurityError, ends_session)
from .hardware_id import get_hardware_id
from .response import PwfResponse

__all__ = ["PwfClient", "__version__"]

__version__ = "1.1.0"

_DEFAULT_BASE_URL = "https://pwfauth.com"

# urllib sends "Python-urllib/3.x" unless told otherwise, and Cloudflare — which
# fronts pwfauth.com — rejects that outright with a 403 and error code 1010, before
# the request ever reaches the app. Identifying ourselves properly is what makes the
# library usable at all against the live server, not a nicety.
_DEFAULT_USER_AGENT = f"pwfauth-python/{__version__} (+https://pwfauth.com)"

_DEFAULT_HEARTBEAT_SECONDS = 30
_DEFAULT_RESET_REASON = "Reset from app"
_MAX_RESET_REASON = 255
_TOO_MANY_REQUESTS = 429

_NETWORK_LOST_MESSAGE = ("Cannot reach the license server. Please check your connection "
                         "and sign in again.")
_CLOCK_SKEW_MESSAGE = ("Cannot verify your license because this computer's date and time "
                       "are wrong. Correct them and sign in again.")


class PwfClient:
    """A licence client for one application. Create one and keep it for the app's life.

    ``on_session_ended`` is the callback that matters: assign a function taking
    ``(error_code, message)`` and it fires the moment the licence stops being valid
    on this machine -- a ban, pause, expiry, HWID reset, revoke, maintenance window,
    a password change on an account, or a server that stopped answering. Logging
    alone leaves the licence unenforceable; stop the app there.

    The callback runs on the heartbeat's background thread. GUI toolkits want UI
    work on their own thread: in Tkinter, ``root.after(0, sign_out)``; in Qt, emit a
    signal.
    """

    def __init__(
        self,
        app_secret: str,
        *,
        base_url: str = _DEFAULT_BASE_URL,
        heartbeat_seconds: float | None = None,
        max_heartbeat_failures: int = 3,
        max_rate_limited_beats: int = 10,
        timeout: float = 15.0,
        hardware_id: str | None = None,
        user_agent: str = _DEFAULT_USER_AGENT,
        auto_correct_clock: bool = True,
        max_clock_drift_seconds: int = 300,
    ) -> None:
        """
        :param app_secret:      The 64-character hex secret from App Settings.
        :param base_url:        Another server, e.g. a staging copy.
        :param heartbeat_seconds: Seconds between heartbeats. ``None`` (the default)
            uses the interval the server sends at login.
        :param max_heartbeat_failures: Beats in a row without an encrypted answer
            (no reply, or only a plain refusal) before the session ends with
            ``NETWORK_LOST`` -- or ``CLOCK_SKEW`` when the server blamed this
            computer's clock. At least 1.
        :param max_rate_limited_beats: The separate budget for beats answered with
            HTTP 429. At least 1.
        :param auto_correct_clock: When the server refuses a request because this
            computer's clock is wrong, shift by the server's time and retry once.
        """
        if not app_secret or not isinstance(app_secret, str):
            raise TypeError("app_secret is required.")
        if not isinstance(base_url, str) or not urlparse(base_url).scheme or not urlparse(base_url).netloc:
            raise ValueError("base_url must be an absolute URL, e.g. https://pwfauth.com")
        if max_heartbeat_failures < 1:
            raise ValueError("max_heartbeat_failures must be at least 1, otherwise an "
                             "unreachable server leaves the app running forever.")
        if max_rate_limited_beats < 1:
            raise ValueError("max_rate_limited_beats must be at least 1, otherwise a proxy "
                             "answering 429 forever leaves the app running.")

        self.app_secret = app_secret.strip()
        self.user_agent = user_agent
        self.base_url = base_url.rstrip("/")
        self.heartbeat_seconds = heartbeat_seconds
        self.max_heartbeat_failures = max_heartbeat_failures
        self.max_rate_limited_beats = max_rate_limited_beats
        self.timeout = timeout
        self.auto_correct_clock = auto_correct_clock
        self.hardware_id = hardware_id or get_hardware_id()

        self.on_session_ended: Callable[[str | None, str | None], None] | None = None

        self._crypto = CryptoEnvelope(self.app_secret, max_clock_drift_seconds)
        self._session_id: str | None = None
        self._license_key: str | None = None
        self._server_interval = _DEFAULT_HEARTBEAT_SECONDS
        self._lock = threading.Lock()
        self._stop: threading.Event | None = None
        self._thread: threading.Thread | None = None

    # ── state ────────────────────────────────────────────────────────────────

    @property
    def is_signed_in(self) -> bool:
        return self._session_id is not None

    @property
    def session_id(self) -> str | None:
        return self._session_id

    @property
    def license_key(self) -> str | None:
        """The license key of the current session, or None when signed out."""
        return self._license_key

    @property
    def heartbeat_interval(self) -> float:
        """Seconds between heartbeats: ``heartbeat_seconds`` if set, else the server's."""
        return self.heartbeat_seconds if self.heartbeat_seconds else self._server_interval

    @property
    def clock_offset_seconds(self) -> int:
        """How far this client shifts its clock to match the server (0 normally)."""
        return self._crypto.clock_offset_seconds

    # ── licence lifecycle ────────────────────────────────────────────────────

    def login(self, license_key: str) -> PwfResponse:
        """Activate a licence key on this machine and open a session.

        When the key is bound to another machine the reply carries ``HWID_MISMATCH``
        (``DEVICE_LIMIT`` for multi-device keys): :meth:`reset_hardware_id` lets the
        customer move it here, then call this again.

        :raises PwfSecurityError: an unencrypted "success" -- not the license server.
        :raises PwfHttpError: no usable reply. :raises PwfCryptoError: a reply that
            failed verification (usually the wrong app secret).
        """
        if not license_key or not isinstance(license_key, str):
            raise TypeError("license_key is required.")
        res = self.post_envelope("/api/auth/login.php", {
            "license_key": license_key,
            "hwid": self.hardware_id,
        })
        if res.success:
            self._open_session(res.data.get("session_id"), license_key, res)
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
        """Send one heartbeat. Prefer :meth:`start_heartbeat`, which also obeys the
        kill switch. Raises if called before :meth:`login`."""
        if not self._session_id:
            raise PwfError("Not signed in — call login() before heartbeat().")
        return self.post_envelope("/api/auth/heartbeat.php", {
            "session_id": self._session_id,
            "license_key": self._license_key,
            "hwid": self.hardware_id,
        })

    def logout(self) -> PwfResponse | None:
        """Stop the heartbeat and end the session on the server.

        Returns None when there was no session, or when the server could not be
        reached (it then ends the session on its own timeout). Logging out does not
        unbind the key: it stays bound to this machine. To move the license to
        another computer, use :meth:`reset_hardware_id`.
        """
        if not self._session_id:
            return None
        self.stop_heartbeat()
        session, key = self._session_id, self._license_key
        self._session_id = None
        self._license_key = None
        try:
            return self.post_envelope("/api/auth/logout.php", {
                "session_id": session,
                "license_key": key or "",
            })
        except PwfError:
            return None

    # ── heartbeat loop ───────────────────────────────────────────────────────

    def start_heartbeat(self) -> None:
        """Begin the background heartbeat on a daemon thread.

        It keeps the session alive AND obeys the kill switch: a ban, pause, expiry,
        HWID reset, revoke or maintenance window calls ``on_session_ended`` on the
        next beat. So does losing the server: only an encrypted reply counts as an
        answer, and ``max_heartbeat_failures`` beats in a row without one -- no reply,
        a forged plain "success", or a plain refusal -- end the session with
        ``NETWORK_LOST``, or ``CLOCK_SKEW`` when the server kept rejecting this
        computer's clock. Calling it twice is a no-op.
        """
        if not self._session_id:
            raise PwfError("Not signed in — call login() before start_heartbeat().")
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop = threading.Event()
            self._thread = threading.Thread(target=self._heartbeat_loop, args=(self._stop,),
                                            name="pwfauth-heartbeat", daemon=True)
            self._thread.start()

    def stop_heartbeat(self) -> None:
        """Stop the background heartbeat without ending the server session. Returns at
        once; a beat already in flight finishes quietly and is ignored."""
        with self._lock:
            stop = self._stop
            self._stop = None
            self._thread = None
        if stop is not None:
            stop.set()

    def run_heartbeat(self) -> None:
        """The heartbeat loop itself, blocking: for console apps and services that
        want to wait on it. Returns when the session ends (``on_session_ended`` has
        been called) or after :meth:`stop_heartbeat` from another thread."""
        if not self._session_id:
            raise PwfError("Not signed in — call login() before run_heartbeat().")
        with self._lock:
            self._stop = threading.Event()
            stop = self._stop
        self._heartbeat_loop(stop)

    def _heartbeat_loop(self, stop: threading.Event) -> None:
        # Only an encrypted reply proves the license server answered — nothing else can
        # seal one. Every other outcome is an unanswered beat: no reply, a reply that
        # fails verification, a forged plain "success" (PwfSecurityError), and plain
        # refusals, which the server sends when it cannot verify the request at all.
        # The commonest of those is its replay check rejecting a clock more than five
        # minutes off; treating it as transient (as 1.0.x did) let an app whose clock
        # was moved run forever, deaf to bans.
        unanswered = 0       # beats in a row without an encrypted reply (not 429)
        plain_refusals = 0   #   ...of which were plain refusals from the server
        clock_refusals = 0   #   ...of which blamed this computer's clock
        rate_limited = 0     # beats in a row answered with HTTP 429

        while not stop.wait(self.heartbeat_interval):
            if not self._session_id:
                return
            beat: PwfResponse | None = None
            error: Exception | None = None
            try:
                beat = self.heartbeat()
            except Exception as e:
                error = e
            # Signed out (or stopped) while the beat was in flight: say nothing.
            if stop.is_set() or not self._session_id:
                return

            if error is not None:
                if isinstance(error, PwfHttpError) and error.status == _TOO_MANY_REQUESTS:
                    rate_limited += 1
                    if rate_limited >= self.max_rate_limited_beats:
                        self._end_session(PwfErrorCodes.NETWORK_LOST, _NETWORK_LOST_MESSAGE, stop)
                        return
                    continue
                # No reply, a reply that failed verification, or a forged success. The
                # server may be down, or someone blocked the domain to keep the app
                # running — either way it will not keep this session alive.
                unanswered += 1
                if unanswered >= self.max_heartbeat_failures:
                    self._end_unanswered(plain_refusals, clock_refusals, stop)
                    return
                continue

            if not beat.is_enveloped:
                # A plain reply is a refusal (a plain success raised above). Shared IPs
                # get rate limited legitimately, so 429 has its own, larger budget.
                if beat.status_code == _TOO_MANY_REQUESTS:
                    rate_limited += 1
                    if rate_limited >= self.max_rate_limited_beats:
                        self._end_session(PwfErrorCodes.NETWORK_LOST, _NETWORK_LOST_MESSAGE, stop)
                        return
                    continue
                plain_refusals += 1
                if _is_clock_refusal(beat):
                    clock_refusals += 1
                unanswered += 1
                if unanswered >= self.max_heartbeat_failures:
                    self._end_unanswered(plain_refusals, clock_refusals, stop)
                    return
                continue

            # Encrypted: the server is reachable and the clock is fine. Every count
            # starts over — and neither kind of failure ever resets the other, so
            # alternating them cannot keep the loop alive either.
            unanswered = plain_refusals = clock_refusals = rate_limited = 0
            if beat.success:
                continue
            if ends_session(beat.error_code):
                self._end_session(beat.error_code, beat.message or "Your session has ended.", stop)
                return
            # An unknown encrypted failure: transient, keep beating.

    def _end_unanswered(self, plain_refusals: int, clock_refusals: int, stop: threading.Event) -> None:
        # When every plain refusal in the streak blamed the clock, say so: signing in
        # again cannot work until it is corrected.
        if plain_refusals > 0 and clock_refusals == plain_refusals:
            self._end_session(PwfErrorCodes.CLOCK_SKEW, _CLOCK_SKEW_MESSAGE, stop)
        else:
            self._end_session(PwfErrorCodes.NETWORK_LOST, _NETWORK_LOST_MESSAGE, stop)

    def _end_session(self, error_code: str | None, message: str | None,
                     stop: threading.Event | None = None) -> None:
        if stop is not None:
            stop.set()
        with self._lock:
            if self._stop is stop:
                self._stop = None
                self._thread = None
        self._session_id = None
        self._license_key = None
        callback = self.on_session_ended
        if callback:
            callback(error_code, message)

    def _open_session(self, session_id: str | None, license_key: str | None,
                      res: PwfResponse) -> None:
        self._session_id = session_id
        self._license_key = license_key
        interval = res.data.get("heartbeat_interval")
        if isinstance(interval, (int, float)) and not isinstance(interval, bool) and interval > 0:
            self._server_interval = max(5, interval)

    # ── app content and updates ──────────────────────────────────────────────

    def get_app_info(self) -> PwfResponse:
        """App metadata: name, version, download URL, login message, maintenance flag,
        social links. The values are under ``data["app"]``."""
        return self.get_envelope("/api/app/info.php")

    def get_texts(self, license_key: str | None = None) -> PwfResponse:
        """Remote texts with the key's overrides applied. Defaults to the signed-in key."""
        key = license_key or self._license_key
        if not key:
            raise PwfError("Sign in first, or pass a license key — remote texts are per key.")
        return self.get_envelope("/api/app/text.php", bearer_license_key=key)

    def get_slides(self) -> PwfResponse:
        """The application's active announcement slides."""
        return self.post_envelope("/api/app/slides.php", {"action": "get_slides"})

    def check_update(self, current_version: str, channel: str = "stable") -> PwfResponse:
        """Is there a newer build than ``current_version``? The reply carries
        ``update_available`` and, when true, ``update`` with the version, SHA-256,
        size and download URL.

        :param channel: "stable", "beta" or "alpha".
        """
        if not current_version or not isinstance(current_version, str):
            raise TypeError("current_version is required.")
        return self.post_envelope("/api/update/check.php", {
            "v": current_version,
            "channel": channel or "stable",
            "hwid": self.hardware_id,
            "license_key": self._license_key or "",
        })

    def track_social_click(self, link_id: int) -> PwfResponse:
        """Count a click on one of the app's social links (the numeric ``id`` from
        :meth:`get_app_info`)."""
        if isinstance(link_id, bool) or not isinstance(link_id, int) or link_id <= 0:
            raise TypeError("link_id must be the link's numeric id from get_app_info().")
        return self.post_envelope("/api/app/social-click.php", {"link_id": link_id})

    # ── trials and self-service ──────────────────────────────────────────────

    def create_trial(self) -> PwfResponse:
        """A free trial key for this machine (when the app allows trials)."""
        return self.post_plain("/api/auth/trial.php", {"hwid": self.hardware_id})

    def reset_hardware_id(self, license_key: str, reason: str | None = None) -> PwfResponse:
        """Move a license to a new PC, instantly and without waiting for the developer.

        Unbinds the key from every machine it is bound to, so the next :meth:`login`
        binds it to this one, and ends all of its sessions. The developer decides
        whether self-service moves are allowed and the cooldown between two of them
        (12 hours by default). Typical flow: ``login`` fails with ``HWID_MISMATCH`` or
        ``DEVICE_LIMIT`` → the user confirms → ``reset_hardware_id`` → ``login``.

        Refusals: ``INVALID_KEY``, ``KEY_NOT_ACTIVE``, ``NO_HWID``, ``RATE_LIMITED``
        (the message says how many hours to wait) or ``SELF_RESET_DISABLED``. On
        success ``data["next_reset_at"]`` says when the next move is allowed.
        """
        if not license_key or not isinstance(license_key, str):
            raise TypeError("license_key is required.")
        text = (reason or "").strip() or _DEFAULT_RESET_REASON
        return self.post_plain("/api/customer/reset-hwid.php", {
            "key": license_key.strip(),
            "reason": text[:_MAX_RESET_REASON],
        })

    def request_hardware_reset(self, license_key: str, reason: str = "") -> PwfResponse:
        """Deprecated: queues a reset request that nobody can approve yet, because the
        dashboard does not show these requests. Use :meth:`reset_hardware_id`."""
        warnings.warn("request_hardware_reset() is deprecated: use reset_hardware_id() "
                      "for an instant self-service move.", DeprecationWarning, stacklevel=2)
        if not license_key or not isinstance(license_key, str):
            raise TypeError("license_key is required.")
        return self.post_plain("/api/auth/request-hwid-reset.php", {
            "license_key": license_key,
            "hwid": self.hardware_id,
            "reason": reason,
        })

    # ── user accounts ────────────────────────────────────────────────────────

    def register_account(self, username: str, password: str, license_key: str | None = None,
                         *, email: str | None = None) -> PwfResponse:
        """Create an end-user account.

        With ``license_key`` the account gets the key's time and device limit, and the
        key is used up (see :meth:`register_account_with_key`). Without one, the app's
        sign-up setting decides; an app that wants a key answers ``KEY_REQUIRED``.
        """
        if not username or not password:
            raise TypeError("username and password are required.")
        body: dict = {"username": username, "password": password, "email": email or ""}
        if license_key:
            body["license_key"] = license_key.strip()
        return self.post_plain("/api/auth/account-register.php", body)

    def register_account_with_key(self, username: str, password: str, license_key: str,
                                  email: str | None = None) -> PwfResponse:
        """Create an account with an unused license key: the account gets the key's time
        and device limit, and the key turns ``redeemed`` (it can no longer sign in on its
        own). Refusals: ``INVALID_KEY``, ``KEY_ALREADY_USED``, ``KEY_IN_USE``, ``BANNED``,
        ``PAUSED``, ``EXPIRED``, ``USERNAME_EXISTS``."""
        if not license_key:
            raise TypeError("license_key is required.")
        return self.register_account(username, password, license_key, email=email)

    def account_login(self, username: str, password: str) -> PwfResponse:
        """Sign an account in and open a session bound to this machine -- the
        heartbeat applies exactly as after :meth:`login`."""
        res = self.post_plain("/api/auth/account-login.php", {
            "username": username,
            "password": password,
            "hwid": self.hardware_id,
        })
        if res.success:
            key = res.data.get("license_key")
            if not key and res.license:
                key = res.license.license_key
            self._open_session(res.data.get("session_id"), key, res)
        return res

    def change_account_password(self, username: str, current_password: str | None = None,
                                new_password: str | None = None, *,
                                old_password: str | None = None) -> PwfResponse:
        """Change an account's password. This signs the account out on every device,
        this one included: a running heartbeat reports it through ``on_session_ended``.

        ``old_password=`` is accepted as the 1.0.x name of ``current_password``.
        """
        current = current_password if current_password is not None else old_password
        if not username or not current or not new_password:
            raise TypeError("username, current_password and new_password are required.")
        return self.post_plain("/api/auth/change-password.php", {
            "username": username,
            "current_password": current,
            "new_password": new_password,
        })

    def redeem_key(self, license_key: str, username: str | None = None,
                   password: str | None = None) -> PwfResponse:
        """Add an unused key's time to an account, and use the key up.

        Pass ``username`` and ``password`` (works while the account has expired too),
        or neither to use the account signed in with :meth:`account_login`. The app's
        settings decide whether the time goes on top or starts from now. The reply
        carries ``days_added``, ``lifetime``, ``expires_at``, ``days_remaining`` and
        ``max_devices``. Wrong passwords and unknown keys count toward the sign-in
        lockout (HTTP 429).
        """
        if not license_key or not isinstance(license_key, str):
            raise TypeError("license_key is required.")
        if username or password:
            if not username or not password:
                raise TypeError("Pass both username and password, or neither.")
            body = {"username": username, "password": password, "license_key": license_key.strip()}
        else:
            if not self._session_id:
                raise PwfError("No account is signed in: call account_login() first, "
                               "or pass the username and password.")
            body = {"session_id": self._session_id, "license_key": license_key.strip()}
        return self.post_plain("/api/auth/account-redeem.php", body)

    # ── transports ───────────────────────────────────────────────────────────

    def post_envelope(self, path: str, body: Any = None) -> PwfResponse:
        """POST an encrypted envelope and decrypt the reply.

        A plain JSON failure (a bad app secret, a rate limit) is returned as a failed
        reply as usual; a plain JSON *success* raises :class:`PwfSecurityError`. When
        the server refuses this machine's clock it sends its own time: the client
        shifts its clock by the difference and sends the request once more.
        """
        reply = self._post_envelope_once(path, body)
        if self.auto_correct_clock and self._try_correct_clock(reply):
            reply = self._post_envelope_once(path, body)
        return reply

    def get_envelope(self, path: str, bearer_license_key: str | None = None) -> PwfResponse:
        """GET whose reply is encrypted. A plain *success* raises PwfSecurityError."""
        headers = {"X-App-Secret": self.app_secret}
        if bearer_license_key:
            headers["Authorization"] = "Bearer " + bearer_license_key
        return self._send(path, method="GET", headers=headers, data=None, require_envelope=True)

    def post_plain(self, path: str, body: Any = None) -> PwfResponse:
        """POST unencrypted JSON, for the endpoints that do not use the envelope."""
        return self._send(path, method="POST",
                          headers={"Content-Type": "application/json",
                                   "X-App-Secret": self.app_secret},
                          data=json.dumps(body or {}).encode("utf-8"),
                          require_envelope=False)

    def _post_envelope_once(self, path: str, body: Any) -> PwfResponse:
        return self._send(path, method="POST",
                          headers={"Content-Type": "application/json",
                                   "X-App-Secret": self.app_secret},
                          data=self._crypto.encrypt(json.dumps(body or {})).encode("utf-8"),
                          require_envelope=True)

    def _try_correct_clock(self, reply: PwfResponse) -> bool:
        # The server's plain refusal for a timestamp outside its window carries
        # "reason": "CLOCK_SKEW" and "server_time" (unix seconds). It never sends that
        # refusal encrypted, so only a plain reply qualifies.
        if reply.is_enveloped or reply.data.get("reason") != PwfErrorCodes.CLOCK_SKEW:
            return False
        server_time = reply.data.get("server_time")
        if isinstance(server_time, bool) or not isinstance(server_time, int) or server_time <= 0:
            return False
        self._crypto.clock_offset_seconds = 0
        self._crypto.clock_offset_seconds = server_time - self._crypto.now()
        return True

    def _send(self, path: str, *, method: str, headers: dict, data: bytes | None,
              require_envelope: bool) -> PwfResponse:
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
            # A 4xx still carries the API's JSON refusal worth reading — Cloudflare
            # eats 5xx bodies, which is why the server uses 4xx for API errors.
            status = e.code
            raw = e.read().decode("utf-8", errors="replace")
        except Exception as cause:
            raise PwfHttpError(f"Could not reach the license server: {cause}") from cause

        if not raw.strip():
            raise PwfHttpError(f"The license server returned HTTP {status} with an empty body.",
                               status=status)

        if CryptoEnvelope.looks_like_envelope(raw):
            return PwfResponse.parse(self._crypto.decrypt(raw), is_enveloped=True,
                                     status_code=status)

        try:
            plain = PwfResponse.parse(raw, is_enveloped=False, status_code=status)
        except PwfError:
            # Not JSON: an HTML error page from a proxy is the usual cause, so hand
            # back a snippet instead of "unexpected token <".
            raise PwfHttpError(
                f"The license server returned a non-JSON body (HTTP {status}). "
                "Check the base URL.", status=status, snippet=raw[:200]) from None

        # The API answers failures with its own {success, error_code, message} shape;
        # hand those back so callers can react. Anything else with a failing status is
        # a transport problem (a 401 for a wrong app secret, a CDN page), not an answer.
        if status >= 400 and "success" not in plain.data:
            raise PwfHttpError(f"The license server returned HTTP {status}.", status=status,
                               snippet=raw[:200])

        # Encrypted endpoints seal EVERY reply once the request is verified; only
        # refusals before that point travel as plain JSON, and those are all failures.
        # A plain success therefore came from a proxy, a hosts-file redirect or a fake
        # server — and accepting it would let any of them unlock the application.
        if require_envelope and plain.success:
            raise PwfSecurityError(
                "The license server's reply was not encrypted, so it cannot be trusted.")
        return plain


def _is_clock_refusal(reply: PwfResponse) -> bool:
    if reply.data.get("reason") == PwfErrorCodes.CLOCK_SKEW:
        return True
    message = reply.message or ""
    return reply.error_code == PwfErrorCodes.CRYPTO_ERROR and "expired" in message.lower()
