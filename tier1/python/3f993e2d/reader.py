import os

BASE = "/srv/reports"


def contents(name):
    cleaned = name
    while "../" in cleaned:
        cleaned = cleaned.replace("../", "")
    with open(os.path.join(BASE, cleaned)) as handle:
        return handle.read()
