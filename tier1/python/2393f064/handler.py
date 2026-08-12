import os


BASE = "/srv/reports"


def handle(name):
    target = os.path.normpath(os.path.join(BASE, name))
    if not target.startswith(BASE + os.sep):
        return ""
    with open(target) as handle_:
        return handle_.read()
