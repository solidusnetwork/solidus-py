//! The native half of `solidus-sdk`: BBS+ only.
//!
//! WHY THIS EXISTS AT ALL. P0 (2026-08-07) checked PyPI rather than assuming:
//! there is no usable native Python BBS+ implementation. `bbs` is an empty
//! 0.0.1 placeholder, `ursa` is gone, and `blspy`/`py_ecc` are BLS primitives —
//! using them would mean implementing `draft-irtf-cfrg-bbs-signatures` in
//! Python, which is a research project rather than an SDK task. Binding
//! `solidus-crypto` gives byte-parity with `zkryptium 0.6`, which is what the
//! conformance vectors actually encode.
//!
//! WHY IT STAYS SMALL. Every function here is a platform the wheel matrix has
//! to build for. Everything expressible in pure Python — base58, BLAKE3
//! addressing, the derivation hierarchy, DID syntax — lives in
//! `python/solidus_network/` and ships in the same wheel with no native cost.
//!
//! WHY PROOF CREATION AND PROOF VERIFICATION ARE SEPARATE CALLS. The obvious
//! shape is one `create_and_verify` function, and it would be shorter. It would
//! also pass with a completely broken proof serialisation, because the proof
//! would never leave Rust's memory. Splitting them forces the proof through
//! `to_hex`/`from_hex` — the wire form a real holder actually sends a real
//! verifier — so the conformance run exercises the path Python users will use.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use solidus_crypto::bbs::{BbsProof, BbsPublicKey, BbsSecretKey, BbsSignature};

fn value_err<E: std::fmt::Debug>(e: E) -> PyErr {
    PyValueError::new_err(format!("{e:?}"))
}

fn as_refs(messages: &[Vec<u8>]) -> Vec<&[u8]> {
    messages.iter().map(|m| m.as_slice()).collect()
}

/// Derive the BBS+ public key for a 32-byte secret key, as lowercase hex.
///
/// `from_bytes`, never `from_ikm`: implementations disagree about BBS KeyGen,
/// which is why the vector publishes a derived public key alongside the IKM
/// instead of expecting everyone to arrive at the same key from the seed.
#[pyfunction]
fn bbs_public_key_hex(secret_key: [u8; 32]) -> PyResult<String> {
    let sk = BbsSecretKey::from_bytes(&secret_key).map_err(value_err)?;
    Ok(sk.public_key().to_hex())
}

/// Verify a BBS+ signature over the full message vector under a header.
///
/// Returns `False` for a signature that does not verify. Raises `ValueError`
/// only when an input cannot be parsed at all — a caller must be able to tell
/// "this credential is invalid" from "you passed me garbage".
#[pyfunction]
fn bbs_verify(
    signature_hex: &str,
    public_key_hex: &str,
    header: Vec<u8>,
    messages: Vec<Vec<u8>>,
) -> PyResult<bool> {
    let pk = BbsPublicKey::from_hex(public_key_hex).map_err(value_err)?;
    let sig = BbsSignature::from_hex(signature_hex).map_err(value_err)?;
    Ok(sig.is_valid(&pk, &header, &as_refs(&messages)))
}

/// Holder side: produce a selective-disclosure proof, as lowercase hex.
///
/// `disclosed_indices` must be strictly ascending and in range; the crate
/// rejects anything else rather than silently reordering, because a proof over
/// a reordered index set verifies against the wrong claims.
#[pyfunction]
fn bbs_create_proof(
    signature_hex: &str,
    public_key_hex: &str,
    header: Vec<u8>,
    presentation_header: Vec<u8>,
    messages: Vec<Vec<u8>>,
    disclosed_indices: Vec<usize>,
) -> PyResult<String> {
    let pk = BbsPublicKey::from_hex(public_key_hex).map_err(value_err)?;
    let sig = BbsSignature::from_hex(signature_hex).map_err(value_err)?;
    let proof = sig
        .create_proof(
            &pk,
            &header,
            &presentation_header,
            &as_refs(&messages),
            &disclosed_indices,
        )
        .map_err(value_err)?;
    Ok(proof.to_hex())
}

/// Verifier side: check a proof against the claims the holder says it discloses.
///
/// The verifier never sees the undisclosed messages, and never sees the
/// signature — that is the entire point. It sees the proof, the issuer's public
/// key, and the (index, message) pairs being asserted.
#[pyfunction]
fn bbs_verify_proof(
    proof_hex: &str,
    public_key_hex: &str,
    header: Vec<u8>,
    presentation_header: Vec<u8>,
    disclosed_indices: Vec<usize>,
    disclosed_messages: Vec<Vec<u8>>,
) -> PyResult<bool> {
    let pk = BbsPublicKey::from_hex(public_key_hex).map_err(value_err)?;
    let proof = BbsProof::from_hex(proof_hex).map_err(value_err)?;
    Ok(proof.is_valid(
        &pk,
        &header,
        &presentation_header,
        &disclosed_indices,
        &as_refs(&disclosed_messages),
    ))
}

#[pymodule]
fn solidus_network_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(bbs_public_key_hex, m)?)?;
    m.add_function(wrap_pyfunction!(bbs_verify, m)?)?;
    m.add_function(wrap_pyfunction!(bbs_create_proof, m)?)?;
    m.add_function(wrap_pyfunction!(bbs_verify_proof, m)?)?;
    Ok(())
}
