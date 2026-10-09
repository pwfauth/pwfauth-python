"""1.1.0: the kill switch can no longer be dodged, a fake plain "success" is refused, a
wrong clock repairs itself, and the calls that sent the wrong field names now work.

Same loopback server as test_client.py: every request is really encrypted, sent,
answered and decrypted.
"""

import json
import threading
import time
import unittest
import warnings

from pwfauth import (CryptoEnvelope, PwfClient, PwfError, PwfErrorCodes, PwfHttpError,
                     PwfSecurityError, __version__, ends_session)

from test_client import SECRET, ServerCase


def _plain(h, obj, status=200):
    h._reply(None, status=status, envelope=False, raw=json.dumps(obj))


def _body(raw):
    """The request body: decrypted when it is an envelope, else plain JSON."""
    if not raw:
        return {}                                    # a GET has no body
    if CryptoEnvelope.looks_like_envelope(raw):
        return json.loads(CryptoEnvelope(SECRET).decrypt(raw))
    return json.loads(raw)


class Base(ServerCase):
    def signed_in(self, **kw):
        self.route("/api/auth/login.php", lambda h, raw: h._reply(
            {"success": True, "session_id": "s", "heartbeat_interval": 30}))
        c = self.client(**kw)
        self.assertTrue(c.login("K").success)
        return c

    def run_until_ended(self, c, wait=5.0):
        ended = threading.Event()
        got = {}
        c.on_session_ended = lambda code, msg: (got.update(code=code, msg=msg), ended.set())
        c.start_heartbeat()
        fired = ended.wait(wait)
        c.stop_heartbeat()
        return fired, got


class TestServerCodesEndTheSession(Base):
    """1.0.x only knew KEY_BANNED & co., which the server never sends."""

    def test_every_code_the_server_kills_with_ends_the_session(self):
        for code in ("BANNED", "PAUSED", "EXPIRED", "HWID_RESET", "MAINTENANCE",
                     "SESSION_REVOKED", "SESSION_EXPIRED", "SESSION_MISMATCH"):
            self.assertTrue(ends_session(code), code)

    def test_a_ban_ends_the_session_with_the_ban_message(self):
        self.route("/api/auth/heartbeat.php", lambda h, raw: h._reply(
            {"success": False, "error_code": "BANNED", "message": "This license key has been banned."}))
        c = self.signed_in(heartbeat_seconds=0.05)
        fired, got = self.run_until_ended(c)
        self.assertTrue(fired)
        self.assertEqual(got, {"code": "BANNED", "msg": "This license key has been banned."})
        self.assertFalse(c.is_signed_in)


class TestKillSwitchCannotBeDodged(Base):
    def test_plain_clock_refusals_end_the_session_with_clock_skew(self):
        # auto_correct_clock off = the 1.1 behaviour of the .NET client: no repair.
        self.route("/api/auth/heartbeat.php", lambda h, raw: _plain(h, {
            "success": False, "error_code": "CRYPTO_ERROR", "message": "Request expired"}, 400))
        c = self.signed_in(heartbeat_seconds=0.05, auto_correct_clock=False)
        fired, got = self.run_until_ended(c)
        self.assertTrue(fired, "a moved clock kept the session alive (the 1.0.x bypass)")
        self.assertEqual(got["code"], PwfErrorCodes.CLOCK_SKEW)

    def test_other_plain_refusals_end_with_network_lost(self):
        self.route("/api/auth/heartbeat.php", lambda h, raw: _plain(h, {
            "success": False, "error_code": "INVALID_APP", "message": "Invalid app secret."}, 401))
        c = self.signed_in(heartbeat_seconds=0.05)
        fired, got = self.run_until_ended(c)
        self.assertTrue(fired)
        self.assertEqual(got["code"], PwfErrorCodes.NETWORK_LOST)

    def test_a_forged_plain_success_counts_as_unanswered(self):
        self.route("/api/auth/heartbeat.php", lambda h, raw: _plain(h, {"success": True}))
        c = self.signed_in(heartbeat_seconds=0.05)
        fired, got = self.run_until_ended(c)
        self.assertTrue(fired, "a fake server answering plain success kept the app running")
        self.assertEqual(got["code"], PwfErrorCodes.NETWORK_LOST)

    def test_rate_limits_have_their_own_budget(self):
        hits = {"n": 0}

        def beat(h, raw):
            hits["n"] += 1
            _plain(h, {"success": False, "error_code": "RATE_LIMITED"}, 429)

        self.route("/api/auth/heartbeat.php", beat)
        c = self.signed_in(heartbeat_seconds=0.02, max_heartbeat_failures=2, max_rate_limited_beats=6)
        fired, got = self.run_until_ended(c)
        self.assertTrue(fired)
        self.assertEqual(got["code"], PwfErrorCodes.NETWORK_LOST)
        self.assertGreaterEqual(hits["n"], 6, "429 used the smaller failure budget")

    def test_an_encrypted_answer_resets_the_failure_count(self):
        n = {"i": 0}

        def beat(h, raw):
            n["i"] += 1
            if n["i"] % 2:
                _plain(h, {"success": False, "error_code": "CRYPTO_ERROR", "message": "bad"}, 400)
            else:
                h._reply({"success": True})

        self.route("/api/auth/heartbeat.php", beat)
        c = self.signed_in(heartbeat_seconds=0.02, max_heartbeat_failures=2)
        fired, _ = self.run_until_ended(c, wait=0.6)
        self.assertFalse(fired, "single misses between good beats must not end the session")

    def test_no_callback_after_logout_while_a_beat_is_in_flight(self):
        def slow(h, raw):
            time.sleep(0.3)
            _plain(h, {"success": False, "error_code": "CRYPTO_ERROR", "message": "x"}, 400)

        self.route("/api/auth/heartbeat.php", slow)
        self.route("/api/auth/logout.php", lambda h, raw: h._reply({"success": True}))
        c = self.signed_in(heartbeat_seconds=0.01, max_heartbeat_failures=1)
        fired = []
        c.on_session_ended = lambda code, msg: fired.append(code)
        c.start_heartbeat()
        time.sleep(0.1)
        t0 = time.time()
        c.logout()
        self.assertLess(time.time() - t0, 0.25, "logout waited for the heartbeat request")
        time.sleep(0.6)
        self.assertEqual(fired, [], "on_session_ended fired after the user logged out")


class TestFakeServerIsRefused(Base):
    def test_login_refuses_a_plain_success(self):
        self.route("/api/auth/login.php", lambda h, raw: _plain(
            h, {"success": True, "session_id": "fake"}))
        c = self.client()
        with self.assertRaises(PwfSecurityError):
            c.login("ANY")
        self.assertFalse(c.is_signed_in)

    def test_app_info_refuses_a_plain_success(self):
        self.route("/api/app/info.php", lambda h, raw: _plain(h, {"success": True, "app": {}}))
        with self.assertRaises(PwfSecurityError):
            self.client().get_app_info()

    def test_plain_refusals_are_still_returned(self):
        self.route("/api/auth/login.php", lambda h, raw: _plain(
            h, {"success": False, "error_code": "INVALID_KEY", "message": "Invalid key."}, 400))
        res = self.client().login("NOPE")
        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "INVALID_KEY")

    def test_a_failing_status_without_the_api_shape_raises(self):
        self.route("/api/auth/login.php", lambda h, raw: _plain(h, {"detail": "nope"}, 401))
        with self.assertRaises(PwfHttpError) as ctx:
            self.client().login("K")
        self.assertEqual(ctx.exception.status, 401)


class TestClockRepair(Base):
    def test_a_wrong_clock_is_corrected_and_the_request_retried(self):
        calls = {"n": 0}
        server_now = int(time.time())

        def login(h, raw):
            calls["n"] += 1
            t = json.loads(raw)["t"]
            if abs(t - server_now) > 300:
                _plain(h, {"success": False, "error_code": "CRYPTO_ERROR", "reason": "CLOCK_SKEW",
                           "server_time": server_now, "message": "the request expired"}, 400)
            else:
                h._reply({"success": True, "session_id": "s"})

        self.route("/api/auth/login.php", login)
        c = self.client()
        c._crypto.clock_offset_seconds = -9 * 3600      # this PC is 9 hours behind
        res = c.login("K")
        self.assertTrue(res.success)
        self.assertEqual(calls["n"], 2, "exactly one retry")
        self.assertLess(abs(c.clock_offset_seconds), 5)

    def test_no_retry_when_switched_off(self):
        calls = {"n": 0}

        def login(h, raw):
            calls["n"] += 1
            _plain(h, {"success": False, "error_code": "CRYPTO_ERROR", "reason": "CLOCK_SKEW",
                       "server_time": int(time.time()), "message": "expired"}, 400)

        self.route("/api/auth/login.php", login)
        res = self.client(auto_correct_clock=False).login("K")
        self.assertFalse(res.success)
        self.assertEqual(calls["n"], 1)

    def test_only_one_retry_per_call(self):
        calls = {"n": 0}

        def login(h, raw):
            calls["n"] += 1
            _plain(h, {"success": False, "error_code": "CRYPTO_ERROR", "reason": "CLOCK_SKEW",
                       "server_time": 1000, "message": "expired"}, 400)

        self.route("/api/auth/login.php", login)
        self.client().login("K")
        self.assertEqual(calls["n"], 2)


class TestFixedCalls(Base):
    def capture(self, path, reply=None, envelope=True):
        seen = {}

        def handler(h, raw):
            seen["body"] = _body(raw)
            seen["headers"] = dict(h.headers)
            if envelope:
                h._reply(reply or {"success": True})
            else:
                _plain(h, reply or {"success": True})

        self.route(path, handler)
        return seen

    def test_check_update_sends_v_and_channel(self):
        seen = self.capture("/api/update/check.php", {"success": True, "update_available": False})
        self.client().check_update("1.4.2", channel="beta")
        self.assertEqual(seen["body"]["v"], "1.4.2")
        self.assertEqual(seen["body"]["channel"], "beta")
        self.assertNotIn("version", seen["body"])

    def test_change_password_sends_current_password(self):
        seen = self.capture("/api/auth/change-password.php", envelope=False)
        self.client().change_account_password("bob", "old-1", "new-2")
        self.assertEqual(seen["body"], {"username": "bob", "current_password": "old-1", "new_password": "new-2"})

    def test_change_password_accepts_the_1_0_keyword(self):
        seen = self.capture("/api/auth/change-password.php", envelope=False)
        self.client().change_account_password("bob", old_password="old-1", new_password="new-2")
        self.assertEqual(seen["body"]["current_password"], "old-1")

    def test_social_click_sends_link_id(self):
        seen = self.capture("/api/app/social-click.php")
        self.client().track_social_click(7)
        self.assertEqual(seen["body"], {"link_id": 7})
        with self.assertRaises(TypeError):
            self.client().track_social_click("discord")

    def test_slides_ask_for_get_slides(self):
        seen = self.capture("/api/app/slides.php", {"success": True, "slides": []})
        self.client().get_slides()
        self.assertEqual(seen["body"], {"action": "get_slides"})

    def test_texts_use_the_signed_in_key(self):
        seen = self.capture("/api/app/text.php", {"success": True, "texts": {}})
        c = self.signed_in()
        c.get_texts()
        self.assertEqual(seen["headers"].get("Authorization"), "Bearer K")


class TestNewCalls(Base):
    def capture_plain(self, path, reply=None):
        seen = {}

        def handler(h, raw):
            seen["body"] = _body(raw)
            seen["enveloped"] = CryptoEnvelope.looks_like_envelope(raw)
            _plain(h, reply or {"success": True})

        self.route(path, handler)
        return seen

    def test_reset_hardware_id(self):
        seen = self.capture_plain("/api/customer/reset-hwid.php",
                                  {"success": True, "message": "Hardware ID has been reset.",
                                   "next_reset_at": "2026-10-06T00:00:00Z"})
        res = self.client().reset_hardware_id(" K-1 ", "New laptop")
        self.assertTrue(res.success)
        self.assertEqual(seen["body"], {"key": "K-1", "reason": "New laptop"})
        self.assertFalse(seen["enveloped"])

    def test_reset_reason_default_and_length(self):
        seen = self.capture_plain("/api/customer/reset-hwid.php")
        self.client().reset_hardware_id("K")
        self.assertEqual(seen["body"]["reason"], "Reset from app")
        self.client().reset_hardware_id("K", "x" * 400)
        self.assertEqual(len(seen["body"]["reason"]), 255)

    def test_register_with_and_without_a_key(self):
        seen = self.capture_plain("/api/auth/account-register.php")
        self.client().register_account("bob", "pw", email="b@x.io")
        self.assertNotIn("license_key", seen["body"])
        self.client().register_account_with_key("bob", "pw", " K-9 ")
        self.assertEqual(seen["body"]["license_key"], "K-9")
        self.client().register_account("bob", "pw", "K-8")          # 1.0.x positional form
        self.assertEqual(seen["body"]["license_key"], "K-8")

    def test_redeem_with_password_or_session(self):
        seen = self.capture_plain("/api/auth/account-redeem.php", {"success": True, "days_added": 30})
        c = self.client()
        c.redeem_key("K-1", "bob", "pw")
        self.assertEqual(seen["body"], {"username": "bob", "password": "pw", "license_key": "K-1"})
        with self.assertRaises(PwfError):
            c.redeem_key("K-1")                         # no account signed in
        with self.assertRaises(TypeError):
            c.redeem_key("K-1", "bob")                  # half the credentials

        self.route("/api/auth/account-login.php", lambda h, raw: _plain(h, {
            "success": True, "session_id": "acc-1", "heartbeat_interval": 30, "user": {"username": "bob"}}))
        self.assertTrue(c.account_login("bob", "pw").success)
        c.redeem_key("K-2")
        self.assertEqual(seen["body"], {"session_id": "acc-1", "license_key": "K-2"})

    def test_request_hardware_reset_is_deprecated(self):
        self.capture_plain("/api/auth/request-hwid-reset.php")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self.client().request_hardware_reset("K", "why")
        self.assertTrue(any(issubclass(x.category, DeprecationWarning) for x in w))


class TestSessionDetails(Base):
    def test_heartbeat_interval_comes_from_the_server(self):
        self.route("/api/auth/login.php", lambda h, raw: h._reply(
            {"success": True, "session_id": "s", "heartbeat_interval": 45}))
        c = self.client()
        c.login("K")
        self.assertEqual(c.heartbeat_interval, 45)
        self.assertEqual(c.license_key, "K")

    def test_a_tiny_server_interval_is_raised_to_five(self):
        self.route("/api/auth/login.php", lambda h, raw: h._reply(
            {"success": True, "session_id": "s", "heartbeat_interval": 1}))
        c = self.client()
        c.login("K")
        self.assertEqual(c.heartbeat_interval, 5)

    def test_an_explicit_interval_wins(self):
        c = self.signed_in(heartbeat_seconds=12)
        self.assertEqual(c.heartbeat_interval, 12)

    def test_logout_when_signed_out_returns_none(self):
        self.assertIsNone(self.client().logout())

    def test_logout_survives_an_unreachable_server(self):
        c = self.signed_in()
        c.base_url = "http://127.0.0.1:9"
        c.timeout = 0.5
        self.assertIsNone(c.logout())
        self.assertFalse(c.is_signed_in)

    def test_user_agent_carries_the_version(self):
        seen = {}
        self.route("/api/app/info.php", lambda h, raw: (
            seen.update(ua=h.headers.get("User-Agent", "")), h._reply({"success": True})))
        self.client().get_app_info()
        self.assertEqual(seen["ua"], f"pwfauth-python/{__version__} (+https://pwfauth.com)")
        self.assertEqual(__version__, "1.2.0")

    def test_options_are_validated(self):
        with self.assertRaises(PwfSecurityError):
            PwfClient(SECRET, base_url="pwfauth.com")
        with self.assertRaises(ValueError):
            PwfClient(SECRET, max_heartbeat_failures=0)
        with self.assertRaises(ValueError):
            PwfClient(SECRET, max_rate_limited_beats=0)


if __name__ == "__main__":
    unittest.main()
