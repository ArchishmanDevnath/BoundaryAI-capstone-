from etl.transform import normalize


def test_normalize():
    assert normalize("  AB ") == "ab"
