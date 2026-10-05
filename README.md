# pwfauth

Official Python client for [PWF Auth](https://pwfauth.com). It covers:

- license keys and hardware-ID binding;
- encrypted sessions with a server-driven kill switch;
- self-service device moves;
- accounts that run on license keys;
- free trials, remote texts and slides, and OTA update checks.

PWF Auth is **100% free**: every feature, unlimited, forever.

```bash
pip install pwfauth
```

Python 3.9+. One dependency, `cryptography`, because Python has no AES in its
standard library. HTTP uses `urllib` from the standard library rather than
`requests`.

## What's new in 1.1.0

- **The kill switch cannot be dodged.** Only an encrypted reply counts as the
  server's answer.
  - A plain refusal no longer keeps the session alive forever. The commonest is
    the server rejecting a clock that was moved more than 5 minutes.
  - Neither does a fake `{"success": true}`.
  - Bans, pauses and expiry end the session with the server's own code
    (`BANNED`, `PAUSED`, `EXPIRED`…) and message.
- **A wrong PC clock repairs itself.** When the server refuses the time, the client
  shifts by the server's clock and retries once. Opt out with
  `auto_correct_clock=False`.
- **Move a license to a new PC:** `reset_hardware_id(key, reason)`.
- **Accounts that run on license keys:** `register_account_with_key()` and
  `redeem_key()`.
- **Fixed:**
  - `check_update()`, `change_account_password()` and `track_social_click()` were
    refused by the server in 1.0.x.
  - The heartbeat now uses the server's interval.
- See [CHANGELOG.md](CHANGELOG.md) for the details and the few behaviour changes.

## Quick start

```python
import os
import sys
from pwfauth import PwfClient

client = PwfClient(os.environ["PWFAUTH_SECRET"])

def on_session_ended(error_code, message):
    """Ban, pause, expiry, HWID reset, revoke, maintenance, or a server that stopped
    answering. Actually stop here — logging alone leaves the licence unenforceable.
    This runs on the heartbeat thread, so os._exit (sys.exit would only end it)."""
    print(f"Session ended ({error_code}): {message}", file=sys.stderr)
    os._exit(1)

client.on_session_ended = on_session_ended

login = client.login("XXXXX-XXXXX-XXXXX-XXXXX")
if not login.success:
    print(login.message, file=sys.stderr)   # safe to show the user
    sys.exit(1)

client.start_heartbeat()   # keeps the session alive AND enforces the kill switch
```

`start_heartbeat()` is what turns a one-time check into a live session. Revoke the key
in your dashboard and `on_session_ended` fires on the user's machine within one
heartbeat. It does not wait for the next launch. A console app or service can call
`client.run_heartbeat()` instead, which blocks until the session ends.

### GUI apps

`on_session_ended` runs on the heartbeat's background thread. Hand the work to your
toolkit's own thread:

```python
client.on_session_ended = lambda code, msg: root.after(0, sign_out, code, msg)   # Tkinter
```

## Moving a license to a new PC

```python
from pwfauth import PwfErrorCodes

login = client.login(key)
if login.error_code in (PwfErrorCodes.HWID_MISMATCH, PwfErrorCodes.DEVICE_LIMIT):
    if ask_user("This key is used on another computer. Move it here?"):
        moved = client.reset_hardware_id(key, "New laptop")
        if moved.success:
            login = client.login(key)
        else:
            show(moved.message)   # e.g. the cooldown: "try again in 11 hours"
```

The move unbinds the key from every machine and ends its sessions. In App Settings
you decide whether customers may move keys themselves, and the cooldown between
two moves (12 hours by default).

## Accounts

```python
client.register_account("bob", "S3cret!pass", email="bob@example.com")
client.register_account_with_key("bob", "S3cret!pass", key)   # when the app wants a key at sign-up
client.account_login("bob", "S3cret!pass")                    # opens a session, like login()
client.redeem_key(another_key)                                # adds the key's time to the account
client.change_account_password("bob", "S3cret!pass", "N3w!pass")
```

- **Keys on accounts:** a key used for sign-up or redeemed onto an account is used
  up. It can no longer sign in on its own, and `login` with it answers
  `KEY_REDEEMED`.
- **Password changes:** changing the password signs the account out on every
  device.

## Reading the licence

```python
lic = login.license
if lic.is_lifetime:
    print("Lifetime licence")
else:
    print(f"Expires {lic.expires_at:%Y-%m-%d} — {lic.days_remaining} day(s) left")
```

`expires_at` is `None` for lifetime keys, because the server sends
`expires_at: null`. Treating that as a date is the most common integration bug
against this API, and the `is_lifetime` flag exists so you never have to.

## Feature flags

```python
if login.get_boolean("pro_export"):
    enable_export()
```

Handles the `1` / `0` / `"true"` forms the dashboard can store.

## Checking a key without using a device seat

```python
status = client.check_key(key)   # no session opened, no seat consumed
```

## Updates

```python
upd = client.check_update("1.4.2")            # channel="beta" / "alpha" also work
if upd.data.get("update_available"):
    print("New version:", upd.data["update"]["version"], upd.data["update"]["download_url"])
```

## Hardware ID

```python
from pwfauth import get_hardware_id
print(get_hardware_id())
```

The ID is derived the same way as in the [.NET](https://www.nuget.org/packages/PWFAuth)
and [Node](https://www.npmjs.com/package/pwfauth) clients. So **the same machine
counts as one device under any SDK**, and switching languages does not use up a
second seat against the licence's device limit.

## Everything else

| Method | What it does |
| --- | --- |
| `login(key)` / `logout()` | Open and close a session (logout does not unbind the key) |
| `check_key(key)` | Read a key's state without a session |
| `heartbeat()` | One manual beat |
| `start_heartbeat()` / `stop_heartbeat()` / `run_heartbeat()` | The heartbeat loop |
| `reset_hardware_id(key, reason)` | Move a license to this PC (self-service) |
| `create_trial()` | Issue a free trial for this machine |
| `get_app_info()` / `get_texts()` / `get_slides()` | Remote app content |
| `check_update(version, channel)` | OTA update check |
| `track_social_click(link_id)` | Count a click on one of the app's social links |
| `register_account()` / `register_account_with_key()` / `account_login()` | User accounts |
| `redeem_key(key)` / `change_account_password()` | Account keys and passwords |
| `post_envelope()` / `get_envelope()` / `post_plain()` | Raw transports |

### Options

`PwfClient` takes these keyword arguments:

| Option | Effect |
| --- | --- |
| `base_url` | Another server |
| `heartbeat_seconds` | Interval between heartbeats; the server's by default |
| `max_heartbeat_failures` | Beats in a row without an encrypted answer before `NETWORK_LOST`; 3 by default |
| `max_rate_limited_beats` | Separate budget for HTTP 429; 10 by default |
| `timeout` | Request timeout |
| `hardware_id` | Use your own hardware ID |
| `user_agent` | The `User-Agent` header to send |
| `auto_correct_clock` | Repair a wrong PC clock automatically |

## Errors

```python
from pwfauth import PwfErrorCodes, PwfHttpError, PwfSecurityError, ends_session

try:
    login = client.login(key)
except PwfSecurityError:
    ...   # an unencrypted "success": not the license server — never unlock on it
except PwfHttpError as e:
    ...   # no usable reply; e.status is 401 for a wrong app secret, 0 for no connection
```

`ends_session(code)` says whether a code means the licence is finished on this
machine. It returns `False` for a code it does not recognise, on purpose. An unknown
code is far more likely to be a new transient condition than a new way of being
banned, and locking a paying user out on a guess is the worse failure.

## Links

- [Dashboard](https://pwfauth.com) · [Docs](https://pwfauth.com/docs) · [API reference](https://pwfauth.com/api-reference)
- [.NET client](https://www.nuget.org/packages/PWFAuth) · [Node client](https://www.npmjs.com/package/pwfauth) · [VS Code extension](https://marketplace.visualstudio.com/items?itemName=PWFAuth.pwfauth)
- [Source code](https://github.com/pwfauth/pwfauth-python) · [Discord](https://discord.gg/hX3ZV2ZtMp)

MIT
