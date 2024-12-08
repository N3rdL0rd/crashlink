import os

from crashlink import *

POSSIBLE_LOCATIONS = [
    "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Dead Cells\\deadcells.exe",
    "C:\\Program Files\\Steam\\steamapps\\common\\Dead Cells\\deadcells.exe",
    "D:\\SteamLibrary\\steamapps\\common\\Dead Cells\\deadcells.exe",
    "E:\\SteamLibrary\\steamapps\\common\\Dead Cells\\deadcells.exe",
    "F:\\SteamLibrary\\steamapps\\common\\Dead Cells\\deadcells.exe",
]


def test_deser_deadcells():
    loc = next((loc for loc in POSSIBLE_LOCATIONS if os.path.exists(loc)), None)
    if loc is None:
        print("Dead Cells not found. Skipping test.")
        assert True
    code = Bytecode.from_path(loc)
    assert code.is_ok()
