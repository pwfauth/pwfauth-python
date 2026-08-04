"""Envelope tests.

The envelope is a protocol, not an implementation detail: the server, the .NET
client, the Node client and this one must all agree byte for byte. These lock the
wire shape and the rejection paths so a "harmless" refactor cannot quietly break
compatibility with the other three.
"""

import base64
import json
import time
import unittest

from pwfauth import CryptoEnvelope, PwfCryptoError

SECRET = "a3f9" * 16
OTHER = "b7c2" * 16


class TestEnvelope(unittest.TestCase):
    def setUp(self):
        self.env = CryptoEnvelope(SECRET)

    def test_round_trips_a_payload(self):
        payload = json.dumps({"license_key": "K-1", "hwid": "abc", "unicode": "مرحبا"})
        self.assertEqual(self.env.decrypt(self.env.encrypt(payload)), payload)

    def test_produces_the_pts_wire_shape(self):
        doc = json.loads(self.env.encrypt("{}"))
        self.assertEqual(set(doc), {"p", "t", "s"})
        self.assertIsInstance(doc["p"], str)
        self.assertIsInstance(doc["t"], int)
        self.assertEqual(len(doc["s"]), 64)                     # hex sha256
        self.assertGreater(len(base64.b64decode(doc["p"])), 16)  # IV + ciphertext

    def test_a_fresh_iv_is_used_every_time(self):
        a = json.loads(self.env.encrypt("{}"))["p"]
        b = json.loads(self.env.encrypt("{}"))["p"]
        self.assertNotEqual(a, b, "IV reuse would leak plaintext structure")

    def test_rejects_a_payload_signed_with_a_different_secret(self):
        foreign = CryptoEnvelope(OTHER).encrypt('{"success":true}')
        with self.assertRaises(PwfCryptoError):
            self.env.decrypt(foreign)

    def test_rejects_a_tampered_ciphertext(self):
        doc = json.loads(self.env.encrypt('{"ok":1}'))
        blob = bytearray(base64.b64decode(doc["p"]))
        blob[-1] ^= 0xFF
        doc["p"] = base64.b64encode(bytes(blob)).decode()
        with self.assertRaises(PwfCryptoError):
            self.env.decrypt(json.dumps(doc))

    def test_rejects_a_stale_timestamp(self):
        doc = json.loads(self.env.encrypt("{}"))
        doc["t"] = int(time.time()) - 4000            # outside the 300s window
        with self.assertRaises(PwfCryptoError):
            self.env.decrypt(json.dumps(doc))

    def test_rejects_malformed_envelopes(self):
        for bad in ("", "not json", "[]", '{"p":"x"}', '{"p":1,"t":1,"s":"x"}'):
            with self.assertRaises(PwfCryptoError):
                self.env.decrypt(bad)

    def test_looks_like_envelope_discriminates(self):
        self.assertTrue(CryptoEnvelope.looks_like_envelope(self.env.encrypt("{}")))
        for plain in ('{"success":true}', "[]", "", "nope"):
            self.assertFalse(CryptoEnvelope.looks_like_envelope(plain))

    def test_key_derivation_matches_the_documented_scheme(self):
        import hashlib
        self.assertEqual(self.env._enc_key, hashlib.sha256(b"enc:" + SECRET.encode()).digest())
        self.assertEqual(self.env._mac_key, hashlib.sha256(b"mac:" + SECRET.encode()).digest())

    def test_requires_a_secret(self):
        for bad in ("", None):
            with self.assertRaises(TypeError):
                CryptoEnvelope(bad)


if __name__ == "__main__":
    unittest.main()
