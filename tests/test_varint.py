from io import BytesIO

import pytest

from crashlink import VarInt


def test_range():
    # values = list(range(0, 20000000, 10000))
    for value in range(0, 20000000, 10000):
        test = VarInt(value)
        ser = BytesIO(test.serialise())
        assert value == VarInt().deserialise(ser).value, f"Failed at {value}"


def test_negatives():
    for value in [1, -1, 127, -127, 128, -128, 0x1FFF, -0x1FFF, 0x2000, -0x2000]:
        print(f"\n=== Testing value: {value} ===")
        vi = VarInt(value)
        encoded = vi.serialise()
        print(f"Encoded bytes: {encoded.hex()}")

        decoded = VarInt().deserialise(BytesIO(encoded))
        print(f"Decoded value: {decoded.value}")

        assert value == decoded.value
