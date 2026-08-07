"""Strict Ed25519 verification.

Spine §2.1: verification must reject small-order public keys and non-canonical
encodings. That gives *strongly binding signatures* — exclusive ownership, the
property a verifiable credential exists to assert. ZIP-215 verification accepts
both and does not.

**The library choice is the decision, not a detail.** This module wraps PyNaCl
(libsodium), which is strict. `cryptography` wraps OpenSSL, which is permissive
about small-order keys — it must not be substituted here, and
`tests/test_ed25519_strict.py` asserts the behaviour rather than trusting this
paragraph, because libsodium's exact rules vary by version.
"""

from __future__ import annotations

import nacl.exceptions
import nacl.signing


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a detached Ed25519 signature, strictly.

    Returns ``False`` for anything that does not verify — including a
    small-order key, a non-canonical scalar, or a wrong-length input. It does
    not raise: a verifier fed untrusted bytes should get an answer, not an
    exception to remember to catch.

    >>> import nacl.signing
    >>> key = nacl.signing.SigningKey(b"\\x01" * 32)
    >>> pub = bytes(key.verify_key)
    >>> sig = key.sign(b"credential").signature
    >>> verify(pub, b"credential", sig)
    True

    A tampered signature fails.

    >>> verify(pub, b"credential", b"\\x00" + sig[1:])
    False

    So does the vacuous identity equation — the all-zeros key with the
    all-zeros signature, which satisfies ZIP-215 for *any* message.

    >>> verify(bytes(32), b"anything at all", bytes(64))
    False
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        nacl.signing.VerifyKey(public_key).verify(message, signature)
    except (nacl.exceptions.BadSignatureError, nacl.exceptions.CryptoError, ValueError):
        return False
    return True


def verify_multibase(public_key_multibase: str, message: bytes, signature: bytes) -> bool:
    """Same, taking the `publicKeyMultibase` straight from a DID Document.

    >>> from .did import public_key_multibase
    >>> import nacl.signing
    >>> key = nacl.signing.SigningKey(b"\\x02" * 32)
    >>> mb = public_key_multibase(bytes(key.verify_key))
    >>> verify_multibase(mb, b"credential", key.sign(b"credential").signature)
    True
    """
    from .did import decode_public_key_multibase

    try:
        public_key = decode_public_key_multibase(public_key_multibase)
    except ValueError:
        return False
    return verify(public_key, message, signature)


__all__ = ["verify", "verify_multibase"]
