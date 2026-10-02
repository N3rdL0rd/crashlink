from crashlink.core import StringsBlock


def _block(*values: str) -> StringsBlock:
    block = StringsBlock()
    block.value = list(values)
    return block


def test_find_or_add_returns_first_index_of_a_duplicate_and_appends_new_strings():
    block = _block("a", "b", "a")
    assert block.find_or_add("a") == 0
    assert block.find_or_add("c") == 3
    assert block.find_or_add("c") == 3
    assert block.value == ["a", "b", "a", "c"]


def test_find_or_add_sees_strings_added_or_swapped_in_outside_it():
    block = _block("a")
    assert block.find_or_add("a") == 0
    block.value.extend(["b", "c"])
    assert block.find_or_add("c") == 2
    block.value = ["x", "y"]
    assert block.find_or_add("y") == 1
    assert block.find_or_add("a") == 2
    assert block.value == ["x", "y", "a"]


def test_set_keeps_lookup_exact():
    block = _block("a", "b")
    assert block.find_or_add("b") == 1
    block.set(1, "c")
    assert block.find_or_add("c") == 1
    assert block.find_or_add("b") == 2
    assert block.value == ["a", "c", "b"]


def test_direct_item_assignment_never_returns_a_stale_index():
    block = _block("a", "b")
    assert block.find_or_add("b") == 1
    block.value[1] = "c"
    assert block.find_or_add("b") == 2
    assert block.value[block.find_or_add("c")] == "c"
