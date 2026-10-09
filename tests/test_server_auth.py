import json
from pathlib import Path
import unittest
from unittest.mock import patch
from pwfauth import PwfClient, PwfSecurityError, CryptoEnvelope
from pwfauth.server_auth import verify_reply

class ServerAuthTests(unittest.TestCase):
    def test_real_server_signature_and_tampering(self):
        v = json.loads(Path(__file__).with_name('signed-reply.json').read_text())
        def check(x):
            verify_reply(x['nonce'], x['method'], x['path'], x['request'].encode(), x['status'], x['body'].encode(), x['signature'])
        check(v)
        for field, value in [('nonce', 'b'*64), ('method', 'GET'), ('path', '/api/auth/heartbeat.php'), ('request', '{}'), ('status', 401), ('body', '{}'), ('signature', ''), ('signature', 'AAAA'), ('signature', '!')]:
            with self.subTest(field=field, value=value), self.assertRaises(PwfSecurityError): check({**v, field:value})

    def test_forbidden_origins_and_runtime_mutation(self):
        for url in ['http://pwfauth.com', 'http://127.0.0.1:8080', 'https://evil.test', 'https://pwfauth.com.evil.test', 'https://pwfauth.com@evil.test', 'https://pwfauth.com:444', 'https://pwfauth.com/api']:
            with self.subTest(url=url), self.assertRaises(PwfSecurityError): PwfClient('a'*64, base_url=url)
        client = PwfClient('a'*64)
        client.base_url = 'http://127.0.0.1:8080'
        with self.assertRaises(PwfSecurityError): client.login('anything')

    def test_unsigned_reply_rejected_before_parsing(self):
        class Reply:
            status = 200
            headers = {}
            def read(self): return CryptoEnvelope("a"*64).encrypt('{"success":true,"session_id":"fake"}').encode()
            def __enter__(self): return self
            def __exit__(self, *args): pass
        with patch('urllib.request.OpenerDirector.open', return_value=Reply()):
            client = PwfClient('a'*64)
            with self.assertRaises(PwfSecurityError): client.login('anything')
            self.assertFalse(client.is_signed_in)
