ITEMS = list(range(100))
PAGE_SIZE = 10


def get_page(page):
    start = page * PAGE_SIZE
    return ITEMS[start:start + PAGE_SIZE + 1]
