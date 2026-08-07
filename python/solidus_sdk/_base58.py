"""Base58 (Bitcoin alphabet). Vendored rather than pulled in as a dependency —
it is thirty lines and the alphabet is consensus-relevant."""

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {c: i for i, c in enumerate(ALPHABET)}


def encode(data: bytes) -> str:
    """Encode bytes as base58btc.

    >>> encode(b"\\x00\\x00\\x01")
    '112'
    """
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = ALPHABET[rem] + out
    # every leading zero byte encodes to one '1'
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def decode(text: str) -> bytes:
    """Decode base58btc to bytes.

    >>> decode("112")
    b'\\x00\\x00\\x01'
    """
    n = 0
    for ch in text:
        if ch not in _INDEX:
            raise ValueError(f"{ch!r} is not in the base58 alphabet")
        n = n * 58 + _INDEX[ch]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + body
