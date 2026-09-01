"""Key derivation — BIP-39 seed, identity key, per-verifier pairwise keys.

⚠ FROZEN. These bytes are locked by `test-vectors/did/derivation-v1.json` and
asserted in the TypeScript SDK, the identity backend, the identity frontend and
the Rust client. **Changing any of it re-keys real users.**

    seed64        = PBKDF2-HMAC-SHA512(NFKD(mnemonic), NFKD("mnemonic"), c=2048, 64)
    identity_priv = seed64[0..32]
    pairwise_priv = HKDF-SHA512(ikm=seed64, salt=b"", info=b"solidus.pairwise.v1"+id, 32)

Note `identity_priv` is a raw slice of the seed and does **not** pass through the
HKDF hierarchy. That asymmetry is deliberate and load-bearing.
"""

import hashlib
import hmac
import unicodedata
from dataclasses import dataclass

import nacl.signing

from .did import did_for, identifier_for

PAIRWISE_INFO_TAG = b"solidus.pairwise.v1"
PBKDF2_ROUNDS = 2048


@dataclass(frozen=True)
class DerivedKey:
    """An Ed25519 keypair with its Solidus identifier already derived."""

    private_key: bytes
    public_key: bytes

    @property
    def identifier(self) -> str:
        return identifier_for(self.public_key)

    def did(self, network: str = "testnet") -> str:
        """`did:solidus:<network>:<identifier>` for this key."""
        return did_for(self.public_key, network)


def _from_private(private_key: bytes) -> DerivedKey:
    signing = nacl.signing.SigningKey(private_key)
    return DerivedKey(private_key=private_key, public_key=bytes(signing.verify_key))


def seed_from_mnemonic(mnemonic: str, passphrase: str = "") -> bytes:
    """BIP-39 mnemonic → 64-byte seed.

    Normalises to NFKD here rather than demanding it from the caller — Python
    ships a normaliser, so refusing to use it would only invite a different seed
    for a visually identical phrase.

    >>> seed = seed_from_mnemonic(" ".join(["abandon"] * 23 + ["art"]))
    >>> len(seed)
    64
    >>> identity_key(seed).identifier
    '3tBoVe6XRtirzr8SdRotGgbkuEQN'
    """
    return hashlib.pbkdf2_hmac(
        "sha512",
        unicodedata.normalize("NFKD", mnemonic).encode(),
        unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode(),
        PBKDF2_ROUNDS,
        dklen=64,
    )


def _hkdf_sha512(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA512 with an explicitly EMPTY salt.

    Empty, not absent. They agree here — HKDF treats an absent salt as a
    zero-filled hash-length block — but they do not agree in every
    implementation, so it is written out.
    """
    prk = hmac.new(b"\x00" * 64, ikm, hashlib.sha512).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha512).digest()
        okm += block
        counter += 1
    return okm[:length]


def identity_key(seed64: bytes) -> DerivedKey:
    """The identity key: `seed64[0..32]`, untouched by the HKDF hierarchy.

    >>> seed = seed_from_mnemonic(" ".join(["abandon"] * 23 + ["art"]))
    >>> identity_key(seed).public_key.hex()
    '1de352e44cd333672593f2334a730e180aaf290de89aa16d480de594e34e2961'
    """
    return _from_private(seed64[:32])


def pairwise_key(seed64: bytes, verifier_id: str) -> DerivedKey:
    """The pairwise key for one verifier.

    A wallet derives a distinct key per verifier so two verifiers cannot
    correlate the same user.

    >>> seed = seed_from_mnemonic(" ".join(["abandon"] * 23 + ["art"]))
    >>> a = pairwise_key(seed, "rp-a.example.com")
    >>> b = pairwise_key(seed, "rp-b.example.com")
    >>> a.identifier != b.identifier  # unlinkable, which is the whole point
    True
    >>> a.did()
    'did:solidus:testnet:3ThmUf3VBefVuaQSBGzC1fcP5iKS'
    """
    return _from_private(_hkdf_sha512(seed64, PAIRWISE_INFO_TAG + verifier_id.encode()))
