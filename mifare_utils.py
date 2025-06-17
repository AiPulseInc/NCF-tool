"""Utility functions for parsing keys and access bits for Mifare cards."""

import re


def parse_key(key_str):
    """Convert a hex key string into a list of integers.

    The key string must contain six two-digit hex values separated by spaces.

    Args:
        key_str: Key string such as "FF FF FF FF FF FF".

    Returns:
        List of six integers representing the key bytes.

    Raises:
        ValueError: If ``key_str`` is not in the expected format.
    """
    parts = key_str.strip().split()
    if len(parts) != 6 or any(not re.fullmatch(r"[0-9a-fA-F]{2}", p) for p in parts):
        raise ValueError("Key must be six two-digit hex values")
    return [int(p, 16) for p in parts]


def parse_access_bits(access_bytes):
    """Return access bit tuples for blocks 0-3."""
    c1, c2, c3 = [], [], []
    for i in range(4):
        c1.append((access_bytes[1] >> (4 + i)) & 1)
        c2.append((access_bytes[2] >> i) & 1)
        c3.append((access_bytes[2] >> (4 + i)) & 1)
    return list(zip(c1, c2, c3))


def mifare_rights(cbits, block):
    """Translate access bits into human-readable rights."""
    if block < 3:
        table = {
            (0, 0, 0): "Read: A/B, Write: A/B, Inc: A/B, Dec: A/B",
            (0, 1, 0): "Read: A/B, Write: -, Inc: -, Dec: -",
            (1, 0, 0): "Read: A/B, Write: B, Inc: B, Dec: A/B",
            (1, 1, 0): "Read: A/B, Write: B, Inc: -, Dec: -",
            (0, 0, 1): "Read: A/B, Write: -, Inc: -, Dec: -",
            (0, 1, 1): "Read: B, Write: B, Inc: B, Dec: B",
            (1, 0, 1): "Read: -, Write: -, Inc: -, Dec: -",
            (1, 1, 1): "Read: B, Write: -, Inc: -, Dec: -",
        }
        return table.get(cbits, "?")

    table = {
        (0, 0, 0): "Key A: Read/Write, Access Bits: Write, Key B: Read/Write",
        (0, 1, 0): "Key A: -, Access Bits: Write, Key B: Read/Write",
        (1, 0, 0): "Key A: Read, Access Bits: -, Key B: Read",
        (1, 1, 0): "Key A: -, Access Bits: -, Key B: Read",
        (0, 0, 1): "Key A: Read/Write, Access Bits: Write, Key B: -",
        (0, 1, 1): "Key A: -, Access Bits: Write, Key B: -",
        (1, 0, 1): "Key A: Read, Access Bits: -, Key B: -",
        (1, 1, 1): "Key A: -, Access Bits: -, Key B: -",
    }
    return table.get(cbits, "?")
