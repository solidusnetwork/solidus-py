"""`did:solidus` identifiers and the W3C verification-method encoding."""

from blake3 import blake3

from ._base58 import ALPHABET, decode, encode

# Multicodec header for an Ed25519 public key (`ed25519-pub`, varint 0xed01).
#
# Required by `Ed25519VerificationKey2020`. This project omitted it until
# 2026-08-07 — encoder and decoder agreed with each other, so we round-tripped
# with ourselves and rejected correctly-encoded keys from everyone else.
ED25519_PUB_MULTICODEC = b"\xed\x01"

_ALPHABET_BYTES = set(ALPHABET.encode())


def identifier_for(public_key: bytes) -> str:
    """The `did:solidus` identifier segment: base58(BLAKE3-256(key)[0..20]).

    >>> identifier_for(bytes.fromhex(
    ...     "1de352e44cd333672593f2334a730e180aaf290de89aa16d480de594e34e2961"))
    '3tBoVe6XRtirzr8SdRotGgbkuEQN'
    """
    return encode(blake3(public_key).digest()[:20])


def did_for(public_key: bytes, network: str = "testnet") -> str:
    """The full `did:solidus:<network>:<identifier>`.

    >>> did_for(bytes.fromhex(
    ...     "1de352e44cd333672593f2334a730e180aaf290de89aa16d480de594e34e2961"))
    'did:solidus:testnet:3tBoVe6XRtirzr8SdRotGgbkuEQN'
    """
    return f"did:solidus:{network}:{identifier_for(public_key)}"


def public_key_multibase(public_key: bytes) -> str:
    """`publicKeyMultibase` for an Ed25519 key — multicodec header, then base58btc.

    Produces the `z6Mk…` form every spec-conformant implementation expects.

    >>> public_key_multibase(bytes.fromhex(
    ...     "248acbdbaf9e050196de704bea2d68770e519150d103b587dae2d9cad53dd930"))
    'z6MkguuUVNj72BEqpY3qHikwFtSCiUWgDGbwiX8pqu5uh3gK'
    """
    return "z" + encode(ED25519_PUB_MULTICODEC + public_key)


def decode_public_key_multibase(multibase: str) -> bytes:
    """The inverse: a `publicKeyMultibase` string back to 32 raw key bytes.

    Without this a Python verifier cannot consume a resolved DID Document at
    all, which is most of what this package is for.

    >>> decode_public_key_multibase(
    ...     "z6MkguuUVNj72BEqpY3qHikwFtSCiUWgDGbwiX8pqu5uh3gK").hex()
    '248acbdbaf9e050196de704bea2d68770e519150d103b587dae2d9cad53dd930'

    ⚠ **Bare 32-byte payloads are accepted, deliberately.** Everything this
    project issued before 2026-08-07 omitted the multicodec header. Those
    documents are real, they are on chain, and refusing them would break every
    credential issued to date. New output always carries the header.

    >>> from ._base58 import encode
    >>> legacy = "z" + encode(bytes.fromhex(
    ...     "248acbdbaf9e050196de704bea2d68770e519150d103b587dae2d9cad53dd930"))
    >>> decode_public_key_multibase(legacy).hex()[:16]
    '248acbdbaf9e0501'

    Anything else raises — a key of the wrong length is not a key.

    >>> decode_public_key_multibase("6MkguuU")
    Traceback (most recent call last):
        ...
    ValueError: publicKeyMultibase must start with 'z' (base58btc)
    """
    if not multibase.startswith("z"):
        raise ValueError("publicKeyMultibase must start with 'z' (base58btc)")
    raw = decode(multibase[1:])
    if len(raw) == 34 and raw[:2] == ED25519_PUB_MULTICODEC:
        return raw[2:]
    if len(raw) == 32:
        return raw
    raise ValueError(
        f"expected 34 bytes with the ed25519-pub header or 32 bare, got {len(raw)}"
    )


def is_valid_identifier(identifier: str) -> bool:
    """SPEC v0.2.0 §4.1: `identifier = 20*28base58char`.

    The bound is arithmetic, not taste — a 20-byte payload cannot encode to
    fewer than 20 characters or more than 28. Spec v0.1.0 allowed 33 and its
    ABNF admitted `0`, `O`, `I` and `l`, so a parser generated from it accepted
    identifiers this method can never mint.

    >>> is_valid_identifier("3tBoVe6XRtirzr8SdRotGgbkuEQN")
    True
    >>> is_valid_identifier("5dXc8vN3kzGm7p6L9HsQrR2hYfBaT1Wj")  # 32 chars, the old spec example
    False
    >>> is_valid_identifier("0OIl000000000000000000")  # not in the alphabet
    False
    """
    return 20 <= len(identifier) <= 28 and set(identifier.encode()) <= _ALPHABET_BYTES


def is_valid_did(did: str) -> bool:
    """Whether a full `did:solidus` string is syntactically valid.

    This is what separates `invalidDid` from `notFound`: "no such DID" implies
    the identifier could have existed.

    >>> is_valid_did("did:solidus:testnet:3tBoVe6XRtirzr8SdRotGgbkuEQN")
    True
    >>> is_valid_did("did:solidus:devnet:3tBoVe6XRtirzr8SdRotGgbkuEQN")
    False
    """
    parts = did.split(":")
    return (
        len(parts) == 4
        and parts[0] == "did"
        and parts[1] == "solidus"
        and parts[2] in ("testnet", "mainnet")
        and is_valid_identifier(parts[3])
    )
