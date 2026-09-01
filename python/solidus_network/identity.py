"""Who someone is: key derivation, identifiers and `did:solidus`.

A facade. Every name here is re-exported from `derivation` and `did`, which
remain the implementation and stay importable. This module exists so that
`from solidus_network import identity` reads the way the npm scope does, without
claiming a bare top-level `identity` in Python's flat namespace, where any
`identity.py` in the caller's own project would silently shadow it.
"""

from .derivation import (
    DerivedKey,
    identity_key,
    pairwise_key,
    seed_from_mnemonic,
)
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
    "is_valid_identifier",
    "is_valid_did",
]
