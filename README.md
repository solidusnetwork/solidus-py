# solidus-sdk

Python SDK for [Solidus Network](https://solidus.network) — `did:solidus` derivation, identifier
validation, W3C verification-method encoding, strict Ed25519, and BBS+ selective disclosure.

**Status: unreleased.** Nothing on PyPI yet. The version is `0.0.0` on purpose — `0.1.0` gets used
once, and a burned version number on PyPI cannot be re-uploaded.

## What it does, and what it does not

**Ships:** address and DID derivation · identifier validation (SPEC v0.2.0 §4.1) ·
`publicKeyMultibase` encoding **and decoding** · strict Ed25519 verification · BBS+ signature
verification and selective-disclosure proofs.

**Not in the first version:**

- **Transaction signing.** A write path means key handling, and in Python that means people pasting
  private keys into notebooks. The read path ships well first.
- **DID resolution over the network.** The encoding and validation this package does are the parts
  implementations get wrong. An HTTP client is not.
- **SD-JWT VC issuance.**

## Install

Not yet. When it publishes:

```bash
pip install solidus-sdk
```

### Installing from source — read this before you try

⚠ **A standalone clone of this repository cannot currently build the native module.** The BBS+
binding depends on `solidus-crypto`, which is **not on crates.io**, so `Cargo.toml` carries a path
that only resolves inside the Solidus monorepo. `pip install git+https://…` will fail at the Rust
build.

This is stated here rather than left for you to discover, and it is a real limitation, not a
formality. Two things lift it, in this order:

1. **Publish `solidus-crypto` to crates.io**, so the dependency resolves for anyone.
2. **A CI wheel matrix** (linux/macos/windows × cp39–cp314), so `pip install solidus-sdk` needs no
   Rust toolchain at all. An sdist alone would force one on every user.

Neither has happened yet. Until then this repository is readable, reviewable and runnable *inside*
the monorepo — and the pure-Python half (derivation, DIDs, multibase, strict Ed25519) has no native
dependency and works from a clone today.

⚠ A git dependency on the public `protocol` repository would **not** fix this. That copy of
`solidus-crypto` predates the feature gating, so `blst` is not optional there and building against
it would drag a C BLS toolchain into every wheel — the exact cost the gating removed.

## Usage

Every example below is executed by the test suite — `pytest --doctest-glob='*.md' README.md`. A
README that stops being true is a test failure. That is not decoration: an outside developer found
four blocks in our TypeScript README that did not compile against the published packages, and this
is the response.

### Derive an identity from a mnemonic

```python
>>> from solidus_sdk import seed_from_mnemonic, identity_key
>>> seed = seed_from_mnemonic(" ".join(["abandon"] * 23 + ["art"]))
>>> key = identity_key(seed)
>>> key.did("testnet")
'did:solidus:testnet:3tBoVe6XRtirzr8SdRotGgbkuEQN'

```

The identity key is `seed64[:32]` — a raw slice, deliberately **not** routed through the HKDF
hierarchy below. That asymmetry is load-bearing and frozen by the conformance vectors.

### Derive a different key for every verifier

A wallet gives each verifier its own key, so two verifiers holding the same user cannot correlate
them.

```python
>>> from solidus_sdk import pairwise_key
>>> a = pairwise_key(seed, "rp-a.example.com")
>>> b = pairwise_key(seed, "rp-b.example.com")
>>> a.identifier == b.identifier
False
>>> a.did()
'did:solidus:testnet:3ThmUf3VBefVuaQSBGzC1fcP5iKS'

```

### Validate a DID before you resolve it

This is what separates `invalidDid` from `notFound` — "no such DID" implies the identifier could
have existed.

```python
>>> from solidus_sdk import is_valid_did
>>> is_valid_did("did:solidus:testnet:3tBoVe6XRtirzr8SdRotGgbkuEQN")
True
>>> is_valid_did("did:solidus:devnet:3tBoVe6XRtirzr8SdRotGgbkuEQN")   # no such network
False
>>> is_valid_did("did:solidus:testnet:0OIl000000000000000000")        # not base58
False

```

### Read a key out of a DID Document, and verify with it

```python
>>> from solidus_sdk import decode_public_key_multibase, ed25519
>>> import nacl.signing
>>> signer = nacl.signing.SigningKey(b"\x07" * 32)
>>> from solidus_sdk import public_key_multibase
>>> verification_method = {
...     "type": "Ed25519VerificationKey2020",
...     "publicKeyMultibase": public_key_multibase(bytes(signer.verify_key)),
... }
>>> signed = signer.sign(b"a credential")
>>> ed25519.verify_multibase(
...     verification_method["publicKeyMultibase"], b"a credential", signed.signature)
True

```

Verification is **strict**: it rejects small-order keys and non-canonical encodings. The vacuous
identity equation — an all-zeros key with an all-zeros signature, which satisfies ZIP-215 for *any*
message — does not verify here.

```python
>>> ed25519.verify(bytes(32), b"anything at all", bytes(64))
False

```

### Verify a BBS+ selective-disclosure proof

The verifier never sees the undisclosed claims and never sees the issuer's signature. It sees the
proof, the issuer's public key, and the `(index, message)` pairs being asserted.

```python
>>> import pytest
>>> _ = pytest.importorskip("solidus_sdk.solidus_sdk_native")  # skips without the wheel
>>> from solidus_sdk import bbs
>>> sk = bytes.fromhex(
...     "363ef9668e4e1cf86b5f2092c51f7c056d6841cec69920cc5d887f68c6cab6d1")
>>> bbs.public_key_hex(sk)[:32]
'9898c245f85011e9092e9a3d20ac204d'

```

*(The `importorskip` line keeps this file runnable as a test in a clone without the compiled
extension. Your own code needs only the `from solidus_sdk import bbs`.)*

Full sign → prove → verify flows, including every negative case, are in `tests/test_vectors.py`
against the published conformance suite.

## API

| module | name | what it is |
|---|---|---|
| `solidus_sdk` | `seed_from_mnemonic(mnemonic, passphrase="")` | BIP-39 → 64-byte seed, NFKD-normalised here |
| | `identity_key(seed64)` → `DerivedKey` | `seed64[:32]`, outside the HKDF tree |
| | `pairwise_key(seed64, verifier_id)` → `DerivedKey` | HKDF-SHA512, one unlinkable key per verifier |
| | `DerivedKey.identifier` · `.did(network)` | base58 address · full `did:solidus:…` |
| `solidus_sdk.did` | `identifier_for(public_key)` | `base58(BLAKE3-256(key)[:20])` |
| | `did_for(public_key, network)` | the full DID string |
| | `public_key_multibase(public_key)` | `z6Mk…`, **with** the `0xed01` multicodec header |
| | `decode_public_key_multibase(mb)` | the inverse; also accepts pre-2026-08-07 headerless keys |
| | `is_valid_identifier(s)` · `is_valid_did(s)` | SPEC v0.2.0 §4.1 syntax |
| `solidus_sdk.ed25519` | `verify(public_key, msg, sig)` | strict; returns `False`, never raises |
| | `verify_multibase(mb, msg, sig)` | the same, straight from a DID Document |
| `solidus_sdk.bbs` | `public_key_hex(secret_key)` | from key **bytes**, never from IKM |
| | `verify(sig_hex, pk_hex, header, messages)` | over the full message vector |
| | `create_proof(…)` → proof hex | holder side |
| | `verify_proof(…)` | verifier side |

## Conformance

`test-vectors/` is published so third parties can check us rather than take our word. This package
runs them itself, and prints its own scope:

```
8/12 vectors in scope. A green run does NOT mean 12/12. Out of scope:
  credential-bundle (3) — agent-identity message map — product layer, not the protocol surface
  did-tx-create (1) — transaction signing is out of v0.1.0 — read path first
```

Eight of twelve, stated openly, is the honest number. **An unimplemented category fails this suite —
it is never skipped.** A runner that quietly passes what it does not understand reports full marks
while checking a fraction, which is worse than having no runner: it manufactures confidence in
exactly the artifact we ask outsiders to trust.

## Ed25519 is strict, and the library choice is why

Verification must reject small-order public keys and non-canonical encodings, which is what gives
*strongly binding signatures* — exclusive ownership, the property a verifiable credential exists to
assert. ZIP-215 verification accepts both and does not.

This package depends on **PyNaCl** (libsodium) rather than `cryptography` (OpenSSL), whose Ed25519
is permissive about small-order keys. libsodium's exact behaviour varies by version, so it is
asserted in `tests/test_ed25519_strict.py` rather than promised here — a test is the only version of
this claim that stays true.

## BBS+ is native, and here is what that costs

There is no usable native Python BBS+ implementation. Checked against PyPI on 2026-08-07: `bbs` is
an empty 0.0.1 placeholder, `ursa` is gone, and `blspy`/`py_ecc` are BLS *primitives* — building on
them would mean implementing `draft-irtf-cfrg-bbs-signatures` in Python.

So BBS+ binds the Rust crate via PyO3, which buys byte-parity with the chain and costs a
per-platform wheel. Everything else is pure Python and ships in the same wheel at no native cost.
The binding is feature-gated to `bbs` only, so no C BLS toolchain enters the build.

⚠ **This is why `pip install solidus-sdk` is not yet a promise the repo can keep.** An sdist alone
forces every user to have a Rust toolchain; wheels have to be built per platform first.

## Development

```bash
uv venv .venv && . .venv/bin/activate
uv pip install maturin pytest blake3 pynacl
maturin develop
pytest
```

`pytest` runs the conformance vectors, every docstring example, **and** every example in this file.

Before believing the suite, break something and watch it fail. Dropping the multicodec header from
`public_key_multibase`, or making `verify()` return `True`, each takes down the specific vectors it
should and nothing else — and two of the four failures we seeded were caught by the doctests
independently of the vector runner.

## Licence

Apache-2.0.
