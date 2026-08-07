"""Spine §2.1: Ed25519 verification must be STRICT, never ZIP-215.

Strict rejects non-canonical encodings and small-order public keys and gives
SBS — strongly binding signatures, i.e. exclusive ownership, i.e.
non-repudiation. ZIP-215 accepts them and does not.

Exclusive ownership is the property a verifiable credential exists to assert, so
this is not a preference. The library choice IS the decision: PyNaCl wraps
libsodium and is strict; `cryptography` wraps OpenSSL and is permissive about
small-order keys.

⚠ libsodium's exact behaviour varies by version, which is why this is a test and
not a sentence in a plan.
"""

import nacl.exceptions
import nacl.signing
import pytest


def test_all_zeros_key_and_signature_is_rejected():
    """The vacuous identity equation: an all-zeros key with an all-zeros
    signature satisfies ZIP-215 and must not satisfy us."""
    verify_key = nacl.signing.VerifyKey(b"\x00" * 32)
    with pytest.raises(nacl.exceptions.BadSignatureError):
        verify_key.verify(b"any message", b"\x00" * 64)


def test_a_real_signature_still_verifies():
    """The control. A strictness test that rejects everything proves nothing."""
    signing = nacl.signing.SigningKey(b"\x01" * 32)
    signed = signing.sign(b"any message")
    assert signing.verify_key.verify(signed) == b"any message"


def test_tampered_signature_is_rejected():
    signing = nacl.signing.SigningKey(b"\x01" * 32)
    sig = bytearray(signing.sign(b"any message").signature)
    sig[0] ^= 0xFF
    with pytest.raises(nacl.exceptions.BadSignatureError):
        signing.verify_key.verify(b"any message", bytes(sig))
