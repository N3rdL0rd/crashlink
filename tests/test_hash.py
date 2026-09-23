import csv
import os
import pytest

from crashlink.hlc import hl_hash_utf8

CSV_PATH = os.path.join(os.path.dirname(__file__), "hashes.csv")


@pytest.mark.skipif(not os.path.exists(CSV_PATH), reason=f"Test dataset not found: {CSV_PATH}")
def test_hash():
    """
    Validates hl_hash_utf8 against hashes from the HashLink runtime's hl_hash_gen
    (hashes.csv, from generate_hashes.c).
    """
    with open(CSV_PATH, "r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)

        for i, row in enumerate(reader):
            if not row:
                continue

            string, expected_hash_str = row
            expected_hash = int(expected_hash_str)

            calculated_hash = hl_hash_utf8(string)

            assert calculated_hash == expected_hash, (
                f"Hash mismatch at CSV row {i + 2} for string: '{string}'.\n"
                f"Expected: {expected_hash}, Got: {calculated_hash}"
            )
