import traceback

from store import lookup


def show(code):
    try:
        return lookup(code)
    except Exception:
        return traceback.format_exc()
