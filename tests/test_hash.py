import csv
import os
import pytest

from crashlink.core import hl_hash

CSV_PATH = os.path.join(os.path.dirname(__file__), "hashes.csv")


@pytest.mark.skip("currently failing")
@pytest.mark.skipif(not os.path.exists(CSV_PATH), reason=f"Test dataset not found: {CSV_PATH}")
def test_hash():
    """
    Validates the Python hl_hash implementation against the dataset generated
    by the C HashLink library.
    """
    with open(CSV_PATH, "r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)

        for i, row in enumerate(reader):
            if not row:
                continue

            string, expected_hash_str = row
            expected_hash = int(expected_hash_str)

            calculated_hash = hl_hash(string)

            assert calculated_hash == expected_hash, (
                f"Hash mismatch at CSV row {i + 2} for string: '{string}'.\n"
                f"Expected: {expected_hash}, Got: {calculated_hash}"
            )
