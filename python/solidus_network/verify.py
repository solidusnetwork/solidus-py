"""Checking what someone presented: Ed25519 signatures and BBS+ proofs.

A facade over `ed25519` and `bbs`, which remain the implementation and stay
importable.

⚠ `ed25519.verify` and `bbs.verify` are different functions with the same name,
so this module does NOT re-export either as a bare `verify`. Doing that would
make `verify.verify(...)` mean one of two things depending on an import order
the caller cannot see. The names below say which primitive is being used, and
the submodules are exposed for anything not covered here.
"""

from . import bbs, ed25519
from .ed25519 import verify as signature
from .ed25519 import verify_multibase as signature_multibase
from .bbs import create_proof as bbs_create_proof
from .bbs import verify as bbs_signature
from .bbs import verify_proof as bbs_proof

__all__ = [
    "signature",
    "signature_multibase",
    "bbs_signature",
    "bbs_proof",
    "bbs_create_proof",
    "ed25519",
    "bbs",
]
