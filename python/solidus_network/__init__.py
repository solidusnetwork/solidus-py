"""Python SDK for the Solidus Network.

The protocol surface — `did:solidus` derivation, identifier validation and
credential verification — without the node internals.

Almost everything here is pure Python. The one native piece is BBS+, because no
usable native Python BBS+ implementation exists and byte-compatibility with the
Rust chain is what the conformance vectors encode.
"""

from . import ed25519, identity, verify
from .derivation import DerivedKey, identity_key, pairwise_key, seed_from_mnemonic
from .did import (
    decode_public_key_multibase,
    did_for,
    identifier_for,
    is_valid_did,
    is_valid_identifier,
    public_key_multibase,
)

__all__ = [
    "DerivedKey",
    "seed_from_mnemonic",
    "identity_key",
    "pairwise_key",
    "identifier_for",
    "did_for",
    "public_key_multibase",
    "decode_public_key_multibase",
    "ed25519",
    "identity",
    "verify",
    "is_valid_identifier",
    "is_valid_did",
]
