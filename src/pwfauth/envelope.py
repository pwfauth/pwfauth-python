"""The AES-256-CBC + HMAC-SHA256 envelope the SDK-grade endpoints speak.

Wire format: ``{"p": base64(IV || ciphertext), "t": unix, "s": hmac_hex(p + t)}``.
Both keys derive from the app secret, so there is no separate key exchange.

This mirrors the server's PayloadCrypto, the .NET client's CryptoEnvelope and the
Node client's envelope.js **byte for byte** -- all four must stay in lockstep, so
treat any change here as a protocol change, not an implementation detail.

Python has no AES in its standard library, which is why ``cryptography`` is the one
dependency this package takes. Everything else is stdlib.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .errors import PwfCryptoError


class CryptoEnvelope:
    """Builds and verifies the ``{p,t,s}`` envelope."""

    def __init__(self, app_secret: str, max_drift_seconds: int = 300) -> None:
        """
        :param app_secret:       The 64-character hex secret from your dashboard.
        :param max_drift_seconds: How far a reply's timestamp may drift before it is
                                  rejected as a replay. Must match the server (300).
        """
        if not app_secret:
            raise TypeError("App secret is required.")
        self._enc_key = hashlib.sha256(("enc:" + app_secret).encode("utf-8")).digest()
        self._mac_key = hashlib.sha256(("mac:" + app_secret).encode("utf-8")).digest()
        self._max_drift = max_drift_seconds

    def encrypt(self, plain_json: str) -> str:
        """Encrypt a request body into the wire envelope."""
        if not isinstance(plain_json, str):
            raise TypeError("plain_json must be a string.")

        iv = os.urandom(16)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded = padder.update(plain_json.encode("utf-8")) + padder.finalize()

        encryptor = Cipher(algorithms.AES(self._enc_key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        p = base64.b64encode(iv + ciphertext).decode("ascii")
        t = int(time.time())
        return json.dumps({"p": p, "t": t, "s": self._hmac_hex(p + str(t))},
                          separators=(",", ":"))

    def decrypt(self, envelope_json: str) -> str:
        """Verify and decrypt a wire envelope back into plain JSON.

        :raises PwfCryptoError: signature failed, timestamp drifted, or malformed.
        """
        try:
            obj = json.loads(envelope_json)
            p, t, s = obj["p"], obj["t"], obj["s"]
            if not isinstance(p, str) or not isinstance(s, str) or not isinstance(t, int):
                raise ValueError("missing fields")
        except Exception as cause:
            raise PwfCryptoError("Invalid envelope format.") from cause

        if not hmac.compare_digest(self._hmac_hex(p + str(t)), s):
            raise PwfCryptoError(
                "HMAC verification failed — wrong app secret, or the payload was tampered with.")

        if abs(int(time.time()) - t) > self._max_drift:
            raise PwfCryptoError(
                "Envelope timestamp is outside the accepted window — "
                "check this machine's system clock.")

        try:
            combined = base64.b64decode(p, validate=True)
        except Exception as cause:
            raise PwfCryptoError("Malformed ciphertext.") from cause
        if len(combined) <= 16:
            raise PwfCryptoError("Malformed ciphertext.")

        try:
            decryptor = Cipher(algorithms.AES(self._enc_key), modes.CBC(combined[:16])).decryptor()
            padded = decryptor.update(combined[16:]) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")
        except Exception as cause:
            raise PwfCryptoError(
                "Decryption failed — wrong app secret or corrupted payload.") from cause

    @staticmethod
    def looks_like_envelope(body: str) -> bool:
        """True when the document looks like a ``{p,t,s}`` envelope."""
        if not body:
            return False
        try:
            o = json.loads(body)
        except Exception:
            return False
        return isinstance(o, dict) and "p" in o and "t" in o and "s" in o

    def _hmac_hex(self, message: str) -> str:
        return hmac.new(self._mac_key, message.encode("utf-8"), hashlib.sha256).hexdigest()
