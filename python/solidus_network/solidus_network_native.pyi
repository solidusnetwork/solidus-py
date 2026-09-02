"""Type stubs for the Rust extension module.

The four functions below are `#[pyfunction]`s in `src/lib.rs`. They are the
whole native surface: everything else in this package is Python.

⚠ This file is what makes the `Typing :: Typed` classifier true. Without it,
`py.typed` would promise type information the extension module cannot provide,
and a user running mypy would get an error from our package rather than from
their own code. Keep the signatures in step with `src/lib.rs` — nothing checks
them against each other, because the extension carries no runtime annotations
to compare against.

Byte sequences are `bytes` on the Python side; the Rust signatures spell them
`Vec<u8>` and `Vec<Vec<u8>>`.
"""

from typing import Sequence

def bbs_public_key_hex(secret_key: bytes) -> str: ...
def bbs_verify(
    signature_hex: str,
    public_key_hex: str,
    header: bytes,
    messages: Sequence[bytes],
) -> bool: ...
def bbs_create_proof(
    signature_hex: str,
    public_key_hex: str,
    header: bytes,
    presentation_header: bytes,
    messages: Sequence[bytes],
    disclosed_indices: Sequence[int],
) -> str: ...
def bbs_verify_proof(
    proof_hex: str,
    public_key_hex: str,
    header: bytes,
    presentation_header: bytes,
    disclosed_indices: Sequence[int],
    disclosed_messages: Sequence[bytes],
) -> bool: ...
