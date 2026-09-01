"""The README's API table must name things that exist.

The doctest gate proves the *examples* run. It says nothing about the reference
table below them, which lists names no example touches — and a doc table that
drifts from the code is the same defect in a smaller font.

So the table is parsed and every name is resolved. Deliberately one-directional:
this fails when the README names something absent, not when the package grows a
private helper. Requiring the table to be exhaustive would make every internal
addition a documentation chore, which is how a check gets deleted.
"""

import importlib
import os
import pathlib
import re

import pytest

README = pathlib.Path(__file__).resolve().parents[1] / "README.md"

# Rows look like:  | `solidus_network.did` | `identifier_for(public_key)` | … |
# and continuation rows carry an empty first cell, inheriting the module above.
ROW = re.compile(r"^\|\s*(`[^`]*`)?\s*\|\s*`([^`]+)`")


def _api_rows():
    rows, module = [], None
    for line in README.read_text().splitlines():
        m = ROW.match(line)
        if not m:
            continue
        if m.group(1):
            module = m.group(1).strip("`")
        if module is None or not module.startswith("solidus_network"):
            continue
        for name in m.group(2).split("·"):
            # "identifier_for(public_key)" -> "identifier_for";
            # "DerivedKey.identifier" -> "DerivedKey", then the attribute.
            symbol = name.strip().split("(")[0].strip().lstrip(".")
            if symbol:
                rows.append((module, symbol))
    return rows


ROWS = _api_rows()


def test_the_table_was_actually_parsed():
    """An empty parametrisation passes silently, which would make this file a
    decoration about decorations."""
    assert len(ROWS) >= 12, f"parsed only {len(ROWS)} API rows from {README}"


@pytest.mark.parametrize("module,symbol", ROWS, ids=lambda x: str(x))
def test_documented_name_exists(module, symbol):
    try:
        obj = importlib.import_module(module)
    except ImportError as exc:
        # `solidus_network.bbs` needs the compiled extension. In a clone without a
        # Rust toolchain it is absent, which says nothing about whether the
        # README is accurate — the same third outcome the vector runner reports.
        message = f"{module} unavailable ({str(exc).splitlines()[0]}) — table row NOT checked"
        if os.environ.get("SOLIDUS_REQUIRE_NATIVE") == "1":
            pytest.fail("SOLIDUS_REQUIRE_NATIVE=1 and " + message)
        pytest.skip(message)
    for part in symbol.split("."):
        assert hasattr(obj, part), f"README documents {module}.{symbol}, which does not exist"
        obj = getattr(obj, part)
