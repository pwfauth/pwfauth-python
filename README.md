# pwfauth

Official Python client for [PWF Auth](https://pwfauth.com) — license keys, hardware-ID
binding, encrypted sessions with a server-driven kill switch, free trials, remote
texts/slides, and OTA update checks.

PWF Auth is **100% free** — every feature, unlimited, forever.

```bash
pip install pwfauth
```

Python 3.9+. One dependency (`cryptography`), because Python has no AES in its
standard library; HTTP uses `urllib` from the stdlib rather than pulling in `requests`.

## Quick start

```python
import os
import sys
from pwfauth import PwfClient

client = PwfClient(os.environ["PWFAUTH_SECRET"])

def on_session_ended(error_code, message):
    """Ban, pause, expiry, HWID reset, revoke, maintenance, or an unreachable
    server. Actually stop here — logging alone leaves the licence unenforceable."""
    print(f"Session ended ({error_code}): {message}", file=sys.stderr)
    sys.exit(1)

client.on_session_ended = on_session_ended

login = client.login("XXXXX-XXXXX-XXXXX-XXXXX")
if not login.success:
    print(login.message, file=sys.stderr)   # safe to show the user
    sys.exit(1)

client.start_heartbeat()   # keeps the session alive AND enforces the kill switch
```

`start_heartbeat()` is what turns a one-time check into a live session. Revoke the key
in your dashboard and `on_session_ended` fires on the user's machine within seconds —
it does not wait for the next launch.

## Reading the licence

```python
lic = login.license
if lic.is_lifetime:
    print("Lifetime licence")
else:
    print(f"Expires {lic.expires_at:%Y-%m-%d} — {lic.days_remaining} day(s) left")
```

`expires_at` is `None` for lifetime keys — the server sends `expires_at: null`, and
treating that as a date is the most common integration bug against this API. The
`is_lifetime` flag exists so you never have to.

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

## Hardware ID

```python
from pwfauth import get_hardware_id
print(get_hardware_id())
```

Derived identically to the [.NET](https://www.nuget.org/packages/PWFAuth) and
[Node](https://www.npmjs.com/package/pwfauth) clients, so **the same machine counts as
one device under any SDK** — switching languages does not burn a second seat against
the licence's device limit.

## Everything else

| Method | What it does |
| --- | --- |
| `login(key)` / `logout()` | Open and close a session |
| `check_key(key)` | Read a key's state without a session |
| `heartbeat()` | One manual beat |
| `start_heartbeat()` / `stop_heartbeat()` | The background loop |
| `create_trial()` | Issue a free trial for this machine |
| `request_hardware_reset(key, reason)` | Ask an admin to unbind a device |
| `get_app_info()` / `get_texts()` / `get_slides()` | Remote app content |
| `check_update(version)` | OTA update check |
| `register_account()` / `account_login()` / `change_account_password()` | User accounts |
| `post_envelope()` / `get_envelope()` / `post_plain()` | Raw transports |

## Error codes

```python
from pwfauth import PwfErrorCodes, ends_session

if ends_session(res.error_code):
    sign_out()
```

`ends_session()` returns `False` for a code it does not recognise, on purpose: an
unknown code is far more likely to be a new transient condition than a new way of
being banned, and locking a paying user out on a guess is the worse failure.

## Links

- [Dashboard](https://pwfauth.com) · [API reference](https://pwfauth.com/api.php)
- [.NET client](https://www.nuget.org/packages/PWFAuth) · [Node client](https://www.npmjs.com/package/pwfauth) · [VS Code extension](https://marketplace.visualstudio.com/items?itemName=PWFAuth.pwfauth)

MIT
