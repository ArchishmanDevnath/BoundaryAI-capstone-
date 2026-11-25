from src.db import get_page


def list_todos(page):
    return {"status": 200, "items": get_page(page)}
