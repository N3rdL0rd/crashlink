from crashlink.core import destaticify


def test_destaticify():
    assert destaticify("$String") == "String"
    assert destaticify("String") == "String"
    assert destaticify("test.test.$Test.Test") == "test.test.$Test.Test"
    assert destaticify("test.test.Test.$Test") == "test.test.Test.Test"
    assert destaticify("test.test.$Test.$Test") == "test.test.$Test.Test"
