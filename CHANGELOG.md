# Changelog

## 1.2.0

- Pin the production HTTPS origin and independently verify every server response.
- Reject missing, forged, tampered and replayed responses before parsing.
- Disable redirects in the default transport. Custom transports are trusted application code and must retain TLS validation and disable redirects.


All notable changes to the [`pwfauth`](https://pypi.org/project/pwfauth/) package.
Versions follow [semantic versioning](https://semver.org).

## 1.1.0 — 2026-10-05

Brings the Python client level with the .NET client (`PWFAuth` 1.3.0).

### Security

- **The kill switch cannot be dodged by moving the clock.** The server refuses a request
  whose timestamp is more than five minutes off with a plain `CRYPTO_ERROR`. In 1.0.x the
  heartbeat treated that as transient and kept the session alive forever, deaf to bans.
  - Now only an encrypted reply counts as an answer.
  - `max_heartbeat_failures` beats in a row without one end the session. The causes can
    be no reply, a plain refusal, or a reply that fails verification.
  - The session ends with `CLOCK_SKEW` when every refusal blamed the clock, and with
    `NETWORK_LOST` otherwise.
  - HTTP 429 has its own budget, `max_rate_limited_beats` (10).
- **A fake plain "success" is refused.** The encrypted endpoints (login, heartbeat,
  check_key, app content) seal every reply once the server has accepted the app secret. A
  plain `{"success": true}` therefore came from a proxy, a hosts-file redirect or a fake
  server.
  - It now raises the new `PwfSecurityError`. In 1.0.x it signed the user in.
  - In the heartbeat it counts as an unanswered beat.
- **The server's kill codes end the session.** `ends_session()` now knows `BANNED`,
  `PAUSED`, `EXPIRED`, `HWID_RESET`, `MAINTENANCE`, `SESSION_REVOKED`, `SESSION_EXPIRED`
  and `SESSION_MISMATCH`. 1.0.x only knew `KEY_BANNED` and similar names, which the server
  never sends. A ban therefore ended the session one beat late, with "Session not found or
  already expired" instead of the ban message.

### Added

- A wrong system clock repairs itself. The server's clock refusal carries
  `"reason": "CLOCK_SKEW"` and `server_time`. The client shifts its timestamps by the
  difference (`clock_offset_seconds`) and sends the request once more. Only one retry per
  call, and only for a plain reply. Opt out with `auto_correct_clock=False`.
- `reset_hardware_id(license_key, reason=None)`: an instant self-service move to a new PC
  (`POST /api/customer/reset-hwid.php`).
  - It unbinds every device of the key and ends its sessions.
  - It is subject to the app's switch and cooldown (12 hours by default).
  - The reason defaults to "Reset from app", up to 255 characters.
- `register_account_with_key(username, password, license_key, email=None)`. The account
  gets the key's time and device limit, and the key is used up.
  `register_account(username, password, license_key=None, *, email=None)` now makes the
  key optional and accepts an e-mail.
- `redeem_key(license_key, username=None, password=None)` adds a key's time to an account
  (`POST /api/auth/account-redeem.php`). It works with the username and password, or
  through the session opened by `account_login()`.
- `run_heartbeat()`: the heartbeat loop, blocking, for console apps and services.
- `PwfClient` options: `max_rate_limited_beats`, `auto_correct_clock` and
  `max_clock_drift_seconds`.
- `PwfClient` properties: `license_key`, `heartbeat_interval` and `clock_offset_seconds`.
- `PwfResponse` fields: `is_enveloped` and `status_code`.
- `PwfErrorCodes` covers everything the server sends:
  - kill codes: `BANNED`, `PAUSED`, `EXPIRED`, `SESSION_REVOKED`, `SESSION_MISMATCH`;
  - sign-in: `INVALID_KEY`, `INVALID_CREDENTIALS`, `DEVICE_LIMIT`, `OPEN_ACCESS_LIMIT`,
    `KEY_REDEEMED`;
  - trials: `TRIAL_DISABLED`, `TRIAL_USED`, `TRIAL_LIMIT`;
  - moves: `KEY_NOT_ACTIVE`, `NO_HWID`, `SELF_RESET_DISABLED`;
  - accounts on keys: `KEY_REQUIRED`, `KEY_ALREADY_USED`, `KEY_IN_USE`, `ALREADY_LIFETIME`,
    `USERNAME_EXISTS`;
  - others: `CRYPTO_ERROR`, `CLOCK_SKEW`.

### Fixed

- `check_update()` sent `version`; the server reads `v`. Every call was refused with
  "current_version is required". It now also sends `channel` (new argument, default
  "stable"), the hardware ID and the signed-in key.
- `change_account_password()` sent `old_password`; the server reads `current_password`, so
  every call was refused. The 1.0.x keyword `old_password=` is still accepted.
- `track_social_click()` sent a platform name; the server counts by `link_id`. It now
  takes the link's numeric id from `get_app_info()`.
- `get_slides()` now sends `{"action": "get_slides"}`, as the endpoint documents.
- The heartbeat uses the interval the server sends at login (at least 5 seconds) instead
  of a fixed 60 seconds. `heartbeat_seconds` still overrides it.
- The README example called `sys.exit()` inside `on_session_ended`. That callback runs on
  the heartbeat thread, where `sys.exit()` ends only that thread and the app kept running.
  The example now uses `os._exit()`, and the README shows the Tkinter way.

### Changed

- `logout()` returns `None` instead of raising when there is no session, and when the
  server cannot be reached. The local session is cleared either way, and the server ends
  its session on its own timeout. Its docstring no longer claims it frees the device seat:
  the key stays bound to this machine.
- `stop_heartbeat()` returns at once. A beat already in flight finishes quietly, and
  `on_session_ended` never fires after a logout.
- A failing HTTP status without the API's JSON shape raises `PwfHttpError` with that
  status, for example 401 for a wrong app secret.
- `request_hardware_reset()` is deprecated, with a `DeprecationWarning`: the dashboard does
  not show those requests. Use `reset_hardware_id()`.
- `User-Agent: pwfauth-python/1.1.0 (+https://pwfauth.com)`.
- Project links point to the documentation (`/docs`) and to the public source repository.

## 1.0.1 — 2026-08-04

- Send a `User-Agent`: urllib's default is blocked by Cloudflare in front of pwfauth.com.

## 1.0.0 — 2026-08-04

- First release.
