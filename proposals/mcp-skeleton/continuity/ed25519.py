"""Ed25519 signatures (RFC 8032), dependency-free.

Why this exists: continuity tokens were signed HS256 over a shared key, which means every
consumer holding the key can *mint*. Asymmetric signing removes that: consumers get the
public key, and minting authority stays in one place.

This is the RFC 8032 reference construction, transcribed and then checked against the
RFC's own test vectors — see `tests/test_ed25519.py`. Hand-rolled crypto is normally a bad
idea; it is defensible here only because (a) the algorithm is fully specified, (b) the
implementation is small enough to read, and (c) it is validated against published vectors
rather than against itself.
"""

import hashlib

p = 2 ** 255 - 19
q = 2 ** 252 + 27742317777372353535851937790883648493
d = -121665 * pow(121666, p - 2, p) % p
I = pow(2, (p - 1) // 4, p)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _inv(x: int) -> int:
    return pow(x, p - 2, p)


def _recover_x(y: int, sign: int):
    if y >= p:
        return None
    x2 = (y * y - 1) * _inv(d * y * y + 1) % p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * I % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


_By = 4 * _inv(5) % p
_Bx = _recover_x(_By, 0)
if _Bx is None:                      # pragma: no cover - cannot happen on this curve
    raise RuntimeError("ed25519 base point is not on the curve")
B = (_Bx, _By)                       # affine (x, y)
IDENTITY = (0, 1)


def _add(P, Q):
    """Affine Edwards addition for a = -1. One inverse per coordinate, no state."""
    x1, y1 = P
    x2, y2 = Q
    xy = d * x1 * x2 * y1 * y2 % p
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + xy) % p
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - xy) % p
    return (x3, y3)


def _mul(s: int, P):
    Q = IDENTITY
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P, Q) -> bool:
    return P[0] % p == Q[0] % p and P[1] % p == Q[1] % p


def _compress(P) -> bytes:
    x, y = P
    return int.to_bytes(y % p | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y)


def _expand(secret: bytes):
    if len(secret) != 32:
        raise ValueError("ed25519 secret must be 32 bytes")
    h = _sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= ~7                      # RFC 8032: clear the 3 least significant bits
    a &= (1 << 254) - 1          # clear bit 255 and above
    a |= 1 << 254                # set bit 254
    return a, h[32:]


def public_key(secret: bytes) -> bytes:
    a, _ = _expand(secret)
    return _compress(_mul(a, B))


def sign(secret: bytes, message: bytes) -> bytes:
    a, prefix = _expand(secret)
    A = _compress(_mul(a, B))
    r = int.from_bytes(_sha512(prefix + message), "little") % q
    Rs = _compress(_mul(r, B))
    h = int.from_bytes(_sha512(Rs + A + message), "little") % q
    s = (r + h * a) % q
    return Rs + int.to_bytes(s, 32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _decompress(public)
    if A is None:
        return False
    Rs = signature[:32]
    s = int.from_bytes(signature[32:], "little")
    if s >= q:
        return False
    R = _decompress(Rs)
    if R is None:
        return False
    h = int.from_bytes(_sha512(Rs + public + message), "little") % q
    return _equal(_mul(s, B), _add(R, _mul(h, A)))


def jwk_from_public(public: bytes, kid: str = "continuity-ed25519-1") -> dict:
    """Publish the public half in JWKS form so consumers can verify without a secret."""
    import base64
    x = base64.urlsafe_b64encode(public).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
            "kid": kid, "x": x}
