import base64
import hashlib
import secrets
from urllib.parse import urlsplit
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from .errors import PwfSecurityError

_KEY = serialization.load_pem_public_key(b"""-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEArJgpZLCvg6z08gEFN4l/
x0FiSYQTsuff7bpb5BHFl7/263J0GOk4YCyt+kXftiURGN4J96KZ4ktAV2tgbu5p
D0LrUa97YLOOkDYIepzbYeSgL8CMQIiDkP86XEp/q2wC7y8weqyRV4fUV8SFNZ3M
gzwRI+aJxYyJGsPheK7Olq2HD5Dx+idjAz8PEbxLWqbNHnS2PdiZ34jC8darQqKI
EW65oBeE6ihulLLDqn1miV8tiEjorROyaCE3oScHzyHB7ZPH2YWcW7vYjgk9ED93
zy3/DrAwyfyWfK2jvb231OFI5+OWKR7XsErlOm3xgAwUkcN3kLxi5/tIbkq3bFOm
OJEr0hWO/nmUmlyCnBA400xjwEUajXmwILugv5QlLkhKtK31upMTTA9XEloerHyC
N4NUGx3+4NqNP07cFkTcH1PpinFRp/iVHLX6M2Zabd+V0rynn2X9STtWmRrKPMMB
AGV+hS8RMg4oliIqmf8FKooQ3HGaL7EoV4n0wgzXG4v9AgMBAAE=
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
