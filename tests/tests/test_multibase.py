"""The multibase round trip, and the legacy shape we are stuck with.

This project omitted the `ed25519-pub` multicodec header until 2026-08-07.
Encoder and decoder agreed with each other, so every round trip passed and
every correctly-encoded key from anyone else was rejected. **A round-trip test
alone would not have caught it** — which is why the vectors check the produced
string against a fixed expected value, and why this file checks the legacy
shape explicitly rather than only checking that our two functions agree.
"""

import json
import pathlib

import pytest

from solidus_network import _base58, did

def _vectors_root() -> pathlib.Path:
    """Walk up until `test-vectors/` appears.

    Counting `..` segments hardcodes one repository layout. This package lives
    at `sdks/python/` inside the monorepo and at the root of its public repo,
    where `test-vectors/` is a submodule — both must work, and neither should
    know about the other.
    """
    # Two known layouts, named rather than guessed at. Counting `..` segments
    # would hardcode one of them; globbing for anything called "test-vectors"
    # would match a stray directory and report it as conformance.
    candidates = (
        pathlib.Path("test-vectors"),                                   # monorepo
        pathlib.Path("vendor/solidus-test-vectors/test-vectors"),       # public repo submodule
    )
    for d in pathlib.Path(__file__).resolve().parents:
        for rel in candidates:
            if (d / rel).is_dir():
                return d / rel
    raise RuntimeError(
        "no test-vectors/ in any parent directory. In a clone of the public repo "
        "this means the submodule is missing: `git submodule update --init`. An "
        "empty vector set must never read as a pass, so this raises."
    )


VECTORS = _vectors_root()

DID_DOCS = sorted((VECTORS / "did").glob("*.json"))


def test_vector_files_were_found():
    """An empty parametrisation passes silently. It must not."""
    assert DID_DOCS, f"no DID vectors under {VECTORS / 'did'}"


@pytest.mark.parametrize("path", DID_DOCS, ids=lambda p: p.name)
def test_every_published_multibase_decodes_to_its_key(path):
    vector = json.loads(path.read_text())
    doc = vector.get("expected", {}).get("didDocument")
    signer = vector.get("input", {}).get("signerPublicKeyHex")
    if not doc or not signer:
        pytest.skip(f"{path.name} carries no DID Document")

    for method in doc["verificationMethod"]:
        assert did.decode_public_key_multibase(method["publicKeyMultibase"]).hex() == signer


def test_legacy_headerless_keys_still_decode():
    """Everything issued before 2026-08-07 has no header. Those documents are
    real and on chain; refusing them breaks every credential issued to date."""
    key = bytes.fromhex(
        "248acbdbaf9e050196de704bea2d68770e519150d103b587dae2d9cad53dd930"
    )
    assert did.decode_public_key_multibase("z" + _base58.encode(key)) == key


def test_new_output_always_carries_the_header():
    """Accepting the legacy shape must not mean emitting it."""
    key = bytes(range(32))
    encoded = did.public_key_multibase(key)
    assert _base58.decode(encoded[1:])[:2] == did.ED25519_PUB_MULTICODEC
    assert did.decode_public_key_multibase(encoded) == key


@pytest.mark.parametrize(
    "bad,why",
    [
        ("6MkguuU", "no multibase prefix"),
        ("z" + _base58.encode(b"\x01" * 31), "31 bytes is not a key"),
        ("z" + _base58.encode(b"\xed\x01" + b"\x01" * 31), "header, wrong body length"),
    ],
)
def test_malformed_input_raises(bad, why):
    with pytest.raises(ValueError):
        did.decode_public_key_multibase(bad)
