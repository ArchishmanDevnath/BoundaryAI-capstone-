from src.auth import check_password


def test_rejects_wrong_password():
    assert not check_password("x", "wrong")
