import os

BASE = "/srv/reports"


def contents(name):
    target = os.path.join(BASE, name)
    with open(target) as handle:
        return handle.read()
