# Changelog

All notable changes to `solidus-network` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Solidus is on **testnet only**. There is no mainnet release yet.

## [Unreleased]

### Added

- `py.typed` and stubs for the Rust extension module, so type checkers see the
  package's annotations instead of treating it as untyped. The
  `Typing :: Typed` classifier now describes something the wheel actually
  ships.
- Package metadata a developer can navigate from: documentation, issues, the
  conformance vectors, and both sibling SDKs are linked from the PyPI page.

## [0.1.0] - 2026-09-02

First release.

### Added

- `did:solidus` derivation and identifier validation, including
  `public_key_multibase` and its inverse.
- Strict Ed25519 verification via PyNaCl. OpenSSL's Ed25519 accepts
  small-order keys that this library rejects, which is why `cryptography` is
  not the dependency.
- BBS+ signature and selective-disclosure-proof verification, through a Rust
  extension built on the ciphersuite from `draft-irtf-cfrg-bbs-signatures`.
- The published conformance vectors run as part of the test suite, from a
  submodule rather than a copy, so the bytes cannot drift from the ones the
  other Solidus SDKs are tested against.
- Wheels for macOS (arm64, x86_64), Linux (x86_64, aarch64) and Windows
  (x64), built `abi3-py39` so one wheel per platform serves Python 3.9 and
  later.
