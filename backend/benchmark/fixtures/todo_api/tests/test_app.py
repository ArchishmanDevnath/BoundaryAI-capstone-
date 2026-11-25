from src.app import list_todos


def test_list():
    assert list_todos(0)["status"] == 201
