"""Test collection rules for the one module that may legitimately be absent.

`solidus_sdk.bbs` raises at import when the compiled extension is missing —
deliberately, so a user importing it gets a sentence explaining what to do
rather than an `AttributeError` three frames later. The cost is that
`--doctest-modules` cannot collect the file at all in a clone without a Rust
toolchain: collection *errors*, and one error stops the entire run.

So collection skips it, and says so. **The message is the point.** A silent
`collect_ignore` would turn "four vectors and one module were never checked"
into a clean green run, which is the failure this suite exists to prevent.

Set `SOLIDUS_REQUIRE_NATIVE=1` — CI does — and the absence becomes a hard error
instead. A wheel that shipped without its native half must not go green.
"""

import os

collect_ignore = []

try:
    import solidus_sdk.bbs  # noqa: F401

    NATIVE = True
except ImportError as exc:
    NATIVE = False
    if os.environ.get("SOLIDUS_REQUIRE_NATIVE") == "1":
        raise RuntimeError(
            f"SOLIDUS_REQUIRE_NATIVE=1 but the native BBS+ extension is missing: {exc}"
        ) from exc
    collect_ignore.append("python/solidus_sdk/bbs.py")


def pytest_report_header(config):
    if NATIVE:
        return "solidus-sdk: native BBS+ extension present — all 8 in-scope vectors will run"
    return (
        "solidus-sdk: native BBS+ extension MISSING. 4 bbs-* vectors and "
        "python/solidus_sdk/bbs.py will NOT be checked. Run `maturin develop`, or "
        "set SOLIDUS_REQUIRE_NATIVE=1 to make this an error."
    )
