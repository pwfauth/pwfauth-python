import base64
import hashlib
import secrets
from urllib.parse import urlsplit
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from .errors import PwfSecurityError

_KEY = serialization.load_pem_public_key(b"""-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAxF7ROKevJDFTnyfYq5S1
QkdwMkY8tMAFhMgi5cMIFdpdCO7xvEtirmVUW+sHvttanDPXMQDGgDKdkbspsHpf
Gbr7vs6ScCltjrGSMx0FansQSvmYp0DVwYVByB0YEhyaej4B+FmwATfHLdFr+XAX
N+C5BWGpVNYfnt0WknasAn/FTncVr01hk4win2iz3C6avZI/T+YgtsWFJioLRmfu
UcMSZ+Hs2zEfCawImh6UPQhsotD8ZHgje8IsYVQTosA7WGX0Cyt1OoT1PJbBxsTO
QaWd6DWqNo4R6GUZzdkb+9Vjj71lmz92Y3rZsff+OIjdbToQqB/sappj4y5tQVtk
lXnDDs/vW45QAWS6PmKjUFuMetkxOSguUO4BbU2Qk4+/Fp60w2y2WSQuCg4g1nrA
aJAwb2b/h009dIlxzTwSPk8nfSlnIRDNbUxQkIUQHs/PgNag1qKc75+kZ6/0VXoP
+2uky8of/4ldFy6FxzRl6FO8jEgrDl8jZpwfiNipz7+pAgMBAAE=
-----END PUBLIC KEY-----""")

def validate_origin(url):
    if not isinstance(url, str) or url.rstrip('/') != 'https://pwfauth.com':
        raise PwfSecurityError('Only https://pwfauth.com is supported.')

def validate_path(path):
    if not isinstance(path, str) or not path.startswith('/') or path.startswith('//') or any(c in path for c in ('\\', '#', '\r', '\n')):
        raise PwfSecurityError('Invalid API path.')

def verify_reply(nonce, method, path, request, status, body, signature):
    material = '\n'.join(('PWF-REPLY-V1', nonce, method, urlsplit(path).path,
        hashlib.sha256(request or b'').hexdigest(), str(status), hashlib.sha256(body).hexdigest()))
    try:
        decoded = base64.b64decode(signature or '', validate=True)
        _KEY.verify(decoded, material.encode(), padding.PKCS1v15(), hashes.SHA256())
    except Exception as exc:
        raise PwfSecurityError('Missing or invalid server signature.') from exc
