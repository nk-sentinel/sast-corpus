import os


BASE = "/srv/reports"


def handle(name):
    target = BASE + "/" + name
    if not target.startswith(BASE):
        return ""
    with open(os.path.normpath(target)) as handle_:
        return handle_.read()
