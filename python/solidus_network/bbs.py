"""BBS+ signatures and selective disclosure.

The only part of this package that is not pure Python. It binds `solidus-crypto`
(`zkryptium 0.6`, BLS12-381-SHA-256) because BBS+ has no usable native Python
implementation — checked against PyPI on 2026-08-07, not assumed. See
`src/lib.rs` for what that check found.

⚠ **Verification is the interesting half.** A binding that verifies a valid
signature and also accepts a tampered one passes every happy-path example anyone
would write. The negative cases in `tests/test_vectors.py` are what make this
module trustworthy; the doctests below are only the shape.
"""

from __future__ import annotations

from typing import Sequence

try:
    from . import solidus_network_native as _native
except ImportError as exc:  # pragma: no cover - exercised by the wheel matrix
    raise ImportError(
        "solidus_network's native BBS+ module is missing. A wheel always ships it; "
        "if you installed from source you need a Rust toolchain, or "
        "`maturin develop` in a checkout."
    ) from exc


def public_key_hex(secret_key: bytes) -> str:
    """Derive the BBS+ public key for a 32-byte secret key.

    The secret key and its expected public key are the ones frozen in
    `test-vectors/bbs/sign-verify-v1.json`.

    >>> sk = bytes.fromhex(
    ...     "363ef9668e4e1cf86b5f2092c51f7c056d6841cec69920cc5d887f68c6cab6d1")
    >>> public_key_hex(sk)[:32]
    '9898c245f85011e9092e9a3d20ac204d'

    The key is derived from the secret **bytes**, not from IKM. Implementations
    disagree about BBS KeyGen, so the conformance vector publishes the derived
    key rather than trusting everyone to reach it from the same seed.
    """
    return _native.bbs_public_key_hex(secret_key)


def verify(
    signature_hex: str,
    public_key_hex_: str,
    header: bytes,
    messages: Sequence[bytes],
) -> bool:
    """Verify a signature over the **full** message vector.

    Returns ``False`` for a signature that does not verify; raises ``ValueError``
    only when an input cannot be parsed. A caller has to be able to tell "this
    credential is invalid" from "you handed me garbage" — collapsing the two is
    how a verifier ends up logging a parse bug as a fraud attempt.
    """
    return _native.bbs_verify(signature_hex, public_key_hex_, header, list(messages))


def create_proof(
    signature_hex: str,
    public_key_hex_: str,
    header: bytes,
    presentation_header: bytes,
    messages: Sequence[bytes],
    disclosed_indices: Sequence[int],
) -> str:
    """Holder side: prove a subset of the messages without revealing the rest.

    ``disclosed_indices`` must be strictly ascending and within range. Anything
    else raises rather than being quietly sorted, because a proof over a
    reordered index set verifies against the wrong claims.
    """
    return _native.bbs_create_proof(
        signature_hex,
        public_key_hex_,
        header,
        presentation_header,
        list(messages),
        list(disclosed_indices),
    )


def verify_proof(
    proof_hex: str,
    public_key_hex_: str,
    header: bytes,
    presentation_header: bytes,
    disclosed_indices: Sequence[int],
    disclosed_messages: Sequence[bytes],
) -> bool:
    """Verifier side: check a proof against the claims it says it discloses.

    The verifier never sees the undisclosed messages and never sees the
    signature. It sees the proof, the issuer's public key, and the
    (index, message) pairs being asserted.
    """
    return _native.bbs_verify_proof(
        proof_hex,
        public_key_hex_,
        header,
        presentation_header,
        list(disclosed_indices),
        list(disclosed_messages),
    )


__all__ = ["public_key_hex", "verify", "create_proof", "verify_proof"]
