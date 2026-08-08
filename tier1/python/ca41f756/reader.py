import os

BASE = "/srv/reports"


def contents(name):
    target = os.path.realpath(os.path.join(BASE, os.path.basename(name)))
    if not target.startswith(BASE + os.sep):
        raise ValueError(name)
    with open(target) as handle:
        return handle.read()
