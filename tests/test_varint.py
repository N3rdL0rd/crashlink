from crashlink import VarInt
from io import BytesIO

def test_range():
    for i in range(0, 20000000, 100):
        test = VarInt(i)
        ser = BytesIO(test.serialise())
        assert i == VarInt().deserialise(ser).value, f"Failed at {i}"
