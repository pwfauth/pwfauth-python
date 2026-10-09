"""Client tests against a REAL http.server that speaks the envelope.

Mocking the transport would leave the crypto, the header contract and the heartbeat
loop untested — which is exactly where a licence client goes wrong. These spin up a
loopback server instead, so a request has to be encrypted, signed, parsed, answered,
and decrypted for a test to pass.
"""

import base64
import hashlib
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import pwfauth.server_auth as server_auth
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from pwfauth import CryptoEnvelope, PwfClient, PwfErrorCodes, PwfHttpError, ends_session

_TEST_SIGNER = rsa.generate_private_key(public_exponent=65537, key_size=3072)
_ORIGIN = server_auth.validate_origin

def _test_origin(url):
    if not url.startswith("http://127.0.0.1:"): _ORIGIN(url)

SECRET = "a3f9" * 16          # 64 hex chars, same shape as a real app secret
OTHER_SECRET = "b7c2" * 16


class _Handler(BaseHTTPRequestHandler):
    routes: dict = {}

    def log_message(self, *args):        # keep the test output clean
        pass

    def _reply(self, obj, status=200, envelope=True, raw=None):
        body = raw if raw is not None else json.dumps(obj)
        if envelope and raw is None:
            body = CryptoEnvelope(SECRET).encrypt(body)
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        material = "\n".join(("PWF-REPLY-V1", self.headers["X-PWF-Nonce"], self.command, self.path.split("?",1)[0], hashlib.sha256(getattr(self,"request_body",b"")).hexdigest(), str(status), hashlib.sha256(data).hexdigest()))
        signature = _TEST_SIGNER.sign(material.encode(), padding.PKCS1v15(), hashes.SHA256())
        self.send_header("X-PWF-Signature", base64.b64encode(signature).decode())
        self.end_headers()
        self.wfile.write(data)

    def _handle(self):
        route = self.routes.get(self.path)
        if route is None:
            self._reply({"success": False, "error_code": "INVALID_REQUEST"}, 404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        self.request_body = raw.encode()
        route(self, raw)

    do_GET = _handle
    do_POST = _handle


class ServerCase(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch("pwfauth.server_auth._KEY", _TEST_SIGNER.public_key()).start()
        patch("pwfauth.client.validate_origin", _test_origin).start()
        _Handler.routes = {}
        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def client(self, **kw):
        return PwfClient(SECRET, base_url=self.base, **kw)

    def route(self, path, fn):
        _Handler.routes[path] = fn


class TestLogin(ServerCase):
    def test_login_captures_session_and_licence(self):
        seen = {}

        def login(h, raw):
            seen["headers"] = dict(h.headers)
            seen["body"] = json.loads(CryptoEnvelope(SECRET).decrypt(raw))
            h._reply({"success": True, "session_id": "sess-1", "user": {
                "license_key": "K-1", "key_type": "days", "expires_at": "2027-01-01T00:00:00Z",
                "days_remaining": 120, "status": "active"}})

        self.route("/api/auth/login.php", login)
        c = self.client()
        res = c.login("K-1")

        self.assertTrue(res.success)
        self.assertTrue(c.is_signed_in)
        self.assertEqual(c.session_id, "sess-1")
        # The app secret must travel as a header, and the HWID inside the envelope.
        self.assertEqual(seen["headers"].get("X-App-Secret"), SECRET)
        self.assertEqual(seen["body"]["hwid"], c.hardware_id)
        self.assertEqual(res.license.days_remaining, 120)
        self.assertFalse(res.license.is_lifetime)

    def test_lifetime_key_reports_no_expiry_instead_of_crashing(self):
        self.route("/api/auth/login.php", lambda h, raw: h._reply(
            {"success": True, "session_id": "s", "user": {"expires_at": None, "key_type": "lifetime"}}))
        res = self.client().login("K")
        self.assertIsNone(res.license.expires_at)
        self.assertTrue(res.license.is_lifetime)

    def test_failed_login_leaves_client_signed_out(self):
        self.route("/api/auth/login.php", lambda h, raw: h._reply(
            {"success": False, "error_code": "KEY_NOT_FOUND", "message": "No such key."}))
        c = self.client()
        res = c.login("nope")
        self.assertFalse(res.success)
        self.assertFalse(c.is_signed_in)
        self.assertEqual(res.error_code, "KEY_NOT_FOUND")


class TestHeartbeat(ServerCase):
    def _login(self, c):
        self.route("/api/auth/login.php", lambda h, raw: h._reply(
            {"success": True, "session_id": "s"}))
        c.login("K")

    def test_kill_switch_ends_the_session(self):
        ended = threading.Event()
        got = {}
        self.route("/api/auth/heartbeat.php", lambda h, raw: h._reply(
            {"success": False, "error_code": "KEY_BANNED", "message": "Banned."}))

        c = self.client(heartbeat_seconds=0.05)
        self._login(c)
        c.on_session_ended = lambda code, msg: (got.update(code=code, msg=msg), ended.set())
        c.start_heartbeat()

        self.assertTrue(ended.wait(5), "on_session_ended never fired")
        self.assertEqual(got["code"], "KEY_BANNED")
        self.assertFalse(c.is_signed_in)

    def test_transient_failure_keeps_the_loop_alive(self):
        hits = {"n": 0}

        def beat(h, raw):
            hits["n"] += 1
            h._reply({"success": False, "error_code": "RATE_LIMITED"})

        self.route("/api/auth/heartbeat.php", beat)
        c = self.client(heartbeat_seconds=0.05)
        self._login(c)
        fired = []
        c.on_session_ended = lambda code, msg: fired.append(code)
        c.start_heartbeat()
        time.sleep(0.4)
        c.stop_heartbeat()

        self.assertGreater(hits["n"], 1, "loop stopped after a transient error")
        self.assertEqual(fired, [], "a rate limit must not end the session")

    def test_unreachable_server_ends_session_with_network_lost(self):
        c = PwfClient(SECRET, base_url="http://127.0.0.1:9",   # discard port
                      heartbeat_seconds=0.05, max_heartbeat_failures=2, timeout=0.5)
        c._session_id = "s"           # skip login; the point is the loop's failure budget
        c._license_key = "K"
        ended = threading.Event()
        got = {}
        c.on_session_ended = lambda code, msg: (got.update(code=code), ended.set())
        c.start_heartbeat()

        self.assertTrue(ended.wait(10), "NETWORK_LOST never fired")
        self.assertEqual(got["code"], "NETWORK_LOST")

    def test_heartbeat_before_login_is_refused(self):
        with self.assertRaises(Exception):
            self.client().heartbeat()


class TestUserAgent(ServerCase):
    """Regression guard for a bug the local test server could never have caught.

    urllib defaults to "Python-urllib/3.x", and Cloudflare — which fronts
    pwfauth.com — answers that with 403 / error code 1010 before the request reaches
    the app. Version 1.0.0 shipped without a User-Agent and simply did not work
    against the live server, while every test here passed.
    """

    def test_a_user_agent_is_always_sent(self):
        seen = {}

        def info(h, raw):
            seen["ua"] = h.headers.get("User-Agent", "")
            h._reply({"success": True})

        self.route("/api/app/info.php", info)
        self.client().get_app_info()

        self.assertTrue(seen["ua"], "no User-Agent header was sent at all")
        self.assertNotIn("Python-urllib", seen["ua"],
                         "urllib's default UA is blocked by Cloudflare")
        self.assertIn("pwfauth-python", seen["ua"])

    def test_user_agent_is_overridable(self):
        seen = {}
        self.route("/api/app/info.php",
                   lambda h, raw: (seen.update(ua=h.headers.get("User-Agent", "")),
                                   h._reply({"success": True})))
        self.client(user_agent="AcmeEditor/2.1").get_app_info()
        self.assertEqual(seen["ua"], "AcmeEditor/2.1")

    def test_user_agent_travels_on_post_too(self):
        seen = {}
        self.route("/api/auth/login.php",
                   lambda h, raw: (seen.update(ua=h.headers.get("User-Agent", "")),
                                   h._reply({"success": True, "session_id": "s"})))
        self.client().login("K")
        self.assertIn("pwfauth-python", seen["ua"])


class TestTransport(ServerCase):
    def test_plain_endpoints_are_not_enveloped(self):
        seen = {}

        def trial(h, raw):
            seen["raw"] = raw
            h._reply({"success": True}, envelope=False, raw=json.dumps({"success": True}))

        self.route("/api/auth/trial.php", trial)
        res = self.client().create_trial()
        self.assertTrue(res.success)
        # The request body must be readable JSON, not an envelope.
        self.assertIn("hwid", json.loads(seen["raw"]))

    def test_non_json_body_raises_with_a_snippet(self):
        self.route("/api/app/info.php", lambda h, raw: h._reply(
            None, status=502, envelope=False, raw="<html><body>Bad Gateway</body></html>"))
        with self.assertRaises(PwfHttpError) as ctx:
            self.client().get_app_info()
        self.assertIn("Bad Gateway", ctx.exception.snippet)

    def test_reply_sealed_with_another_secret_is_rejected(self):
        self.route("/api/app/info.php", lambda h, raw: h._reply(
            None, envelope=False,
            raw=CryptoEnvelope(OTHER_SECRET).encrypt(json.dumps({"success": True}))))
        with self.assertRaises(Exception):
            self.client().get_app_info()


class TestErrorCodes(unittest.TestCase):
    def test_ends_session_classifies_codes(self):
        for code in ("KEY_BANNED", "KEY_EXPIRED", "HWID_MISMATCH", "NETWORK_LOST", "MAINTENANCE"):
            self.assertTrue(ends_session(code), code)
        for code in ("RATE_LIMITED", "SERVER_ERROR", "INVALID_REQUEST", "", None, "SOMETHING_NEW"):
            self.assertFalse(ends_session(code), repr(code))

    def test_unknown_codes_do_not_lock_users_out(self):
        # A code this library has not heard of is far more likely to be a new
        # transient condition than a new way of being banned.
        self.assertFalse(ends_session("A_CODE_FROM_THE_FUTURE"))

    def test_constructor_validates_input(self):
        for bad in ("", None, 123):
            with self.assertRaises(TypeError):
                PwfClient(bad)


if __name__ == "__main__":
    unittest.main()
