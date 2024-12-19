from io import BytesIO

from crashlink import DebugInfo, fileRef


def test_range():
    for k in range(100):
        info = DebugInfo()
        for i in range((25 * k) + 1):
            for j in range(5):
                info.value.append(fileRef(fid=i, line=j))
        ser = BytesIO(info.serialise())
        des = DebugInfo().deserialise(ser, len(info.value))
        assert info == des
