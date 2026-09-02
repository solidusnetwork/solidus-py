"""Runs the published conformance vectors against this package.

Same contract as the Rust runner: an unimplemented category is a FAILURE, never
a skip. A suite that quietly passes what it does not understand reports full
marks while checking a fraction, which is worse than having no suite — it
manufactures confidence in the exact artifact we hand outsiders.

Categories this package deliberately does not own are named in `OUT_OF_SCOPE`
**with a reason**, and the reasons are printed on every run. A bare set of
strings decays into a place to put things that fail; a set that has to carry a
sentence explaining itself is much harder to grow by accident.
"""

import json
import os
import pathlib

import pytest

from solidus_network import derivation, did

# BBS+ is the one part of this package with a compiled extension. In a clone
# without a Rust toolchain it is simply absent, and that is a THIRD outcome —
# neither "passes" nor "we do not implement it". Conflating it with either is
# how a suite starts lying: a crash reads as a broken package, and a silent skip
# reads as a pass.
try:
    from solidus_network import bbs

    NATIVE = True
    NATIVE_ERROR = ""
except ImportError as exc:  # pragma: no cover - depends on how it was installed
    bbs = None
    NATIVE = False
    NATIVE_ERROR = str(exc).split("\n")[0]

# CI must not be allowed to go green on a wheel that shipped without its native
# half. Set this and a missing extension becomes a failure instead of a report.
REQUIRE_NATIVE = os.environ.get("SOLIDUS_REQUIRE_NATIVE") == "1"

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

# Categories this package does not implement, and why. Both entries are
# decisions, not gaps — a gap belongs in the failing column.
OUT_OF_SCOPE = {
    # R6b, taken for the Rust client and holding here: these exercise the
    # agent-identity MESSAGE MAP (owner_binding, capability_scope,
    # spend_mandate), a product-layer schema still in motion. The chain knows
    # only a generic CredentialType. They remain conformance vectors — for the
    # agent-identity SDK, not for this one.
    "credential-bundle": "agent-identity message map — product layer, not the protocol surface",
    # A v0.1.0 scope decision: this package ships the READ path. Implementing
    # this vector means shipping transaction signing, which means key handling,
    # which in Python means people pasting private keys into notebooks. Revisit
    # for v0.2.0 with a deliberate key-handling story, rather than as a side
    # effect of making a vector go green.
    "did-tx-create": "transaction signing is out of v0.1.0 — read path first",
}


def _unhex_all(hexes):
    return [bytes.fromhex(h) for h in hexes]


def _load():
    files = sorted(VECTORS.rglob("*.json"))
    assert files, f"no vectors under {VECTORS} — an empty run must never report success"
    return [(f, json.loads(f.read_text())) for f in files]


ALL = _load()
IN_SCOPE = [(f, v) for f, v in ALL if v["category"] not in OUT_OF_SCOPE]


@pytest.mark.parametrize("path,vector", IN_SCOPE, ids=lambda x: getattr(x, "name", ""))
def test_vector(path, vector):
    category = vector["category"]
    inp, expected = vector.get("input", {}), vector.get("expected", {})

    if category == "hash160":
        from blake3 import blake3

        got = blake3(inp["dataUtf8"].encode()).digest()[:20].hex()
        assert got == expected["hash160Hex"]

    elif category == "did-derivation":
        seed = derivation.seed_from_mnemonic(inp["mnemonic"])
        identity = derivation.identity_key(seed)
        pairwise = derivation.pairwise_key(seed, inp["pairwiseVerifierId"])
        assert identity.public_key.hex() == expected["identityPublicKeyHex"]
        assert identity.identifier == expected["identityAddress"]
        assert pairwise.public_key.hex() == expected["pairwisePublicKeyHex"]
        assert pairwise.did(inp["network"]) == expected["pairwiseDid"]

    elif category in ("did-resolve", "did-deactivate"):
        pk = bytes.fromhex(inp["signerPublicKeyHex"])
        doc = expected["didDocument"]
        assert did.is_valid_did(inp["did"]), f"{inp['did']} fails SPEC v0.2.0 §4.1"
        assert inp["did"].endswith(did.identifier_for(pk))
        # The value the whole multicodec correction was about.
        assert doc["verificationMethod"][0]["publicKeyMultibase"] == did.public_key_multibase(pk)
        assert doc["id"] == inp["did"]
        for key in ("didDocument", "didDocumentMetadata", "didResolutionMetadata"):
            assert expected[key] is not None
        assert expected["didDocumentMetadata"]["deactivated"] == (category == "did-deactivate")

    elif category.startswith("bbs-") and not NATIVE:
        message = (
            f"native BBS+ extension unavailable ({NATIVE_ERROR}) — this vector was "
            f"NOT checked. Build it with `maturin develop`."
        )
        if REQUIRE_NATIVE:
            pytest.fail("SOLIDUS_REQUIRE_NATIVE=1 and " + message)
        pytest.skip(message)

    elif category == "bbs-sign-verify":
        # from_bytes, not from_ikm — the vector publishes both because
        # implementations disagree about BBS KeyGen.
        assert bbs.public_key_hex(bytes.fromhex(inp["secretKeyHex"])) == expected["publicKeyHex"]
        verified = bbs.verify(
            inp["signatureHex"],
            expected["publicKeyHex"],
            bytes.fromhex(inp["headerHex"]),
            _unhex_all(inp["messageHexes"]),
        )
        assert verified is expected["signatureVerifies"]

    elif category in ("bbs-selective-disclosure", "bbs-selective-disclosure-negative"):
        # The negative vector discloses messages the signature never covered.
        # Proof generation still succeeds — the lie is only detectable at
        # verification, which is precisely why the negative case exists.
        field = (
            "liedDisclosedMessageHexes"
            if "liedDisclosedMessageHexes" in inp
            else "disclosedMessageHexes"
        )
        header = bytes.fromhex(inp["headerHex"])
        ph = bytes.fromhex(inp["presentationHeaderHex"])
        proof_hex = bbs.create_proof(
            inp["signatureHex"],
            inp["publicKeyHex"],
            header,
            ph,
            _unhex_all(inp["messageHexes"]),
            inp["disclosedIndices"],
        )
        # Through hex on purpose: a proof that never leaves memory would verify
        # even with a broken serialisation, and the wire form is what a holder
        # actually sends.
        verified = bbs.verify_proof(
            proof_hex,
            inp["publicKeyHex"],
            header,
            ph,
            inp["disclosedIndices"],
            _unhex_all(inp[field]),
        )
        assert verified is expected["proofVerifies"]

    elif category == "bbs-negative-cases":
        header = bytes.fromhex(inp["headerHex"])
        messages = _unhex_all(inp["messageHexes"])
        accepted = []
        for case in inp["cases"]:
            msgs = list(messages)
            if "messageOverrideIndex" in case:
                msgs[case["messageOverrideIndex"]] = bytes.fromhex(case["messageOverrideHex"])
            if bbs.verify(
                inp["signatureHex"],
                case.get("publicKeyOverrideHex", inp["publicKeyHex"]),
                bytes.fromhex(case["headerOverrideHex"]) if "headerOverrideHex" in case else header,
                msgs,
            ):
                accepted.append(case["name"])
        assert expected["allCasesVerifyFalse"] is True
        assert not accepted, f"these cases verified when they must not: {accepted}"

    else:
        pytest.fail(
            f"category {category!r} has no handler. A new vector was published and this "
            f"runner was not taught about it — that is a failure, not a skip."
        )


def test_out_of_scope_is_declared_not_forgotten():
    """The out-of-scope set must match reality, or 'green' quietly narrows."""
    seen = {v["category"] for _, v in ALL}
    unknown = set(OUT_OF_SCOPE) - seen
    assert not unknown, f"OUT_OF_SCOPE names categories no vector uses: {sorted(unknown)}"
    unavailable = 0 if NATIVE else sum(1 for _, v in ALL if v["category"].startswith("bbs-"))
    checked = len(IN_SCOPE) - unavailable
    print(
        f"\n  {checked}/{len(ALL)} vectors CHECKED. "
        f"A green run does NOT mean {len(ALL)}/{len(ALL)}."
    )
    for category, reason in sorted(OUT_OF_SCOPE.items()):
        count = sum(1 for _, v in ALL if v["category"] == category)
        print(f"    out of scope   {category} ({count}) — {reason}")
    if unavailable:
        print(
            f"    UNAVAILABLE    bbs-* ({unavailable}) — native extension missing, "
            f"so these were not checked at all"
        )
