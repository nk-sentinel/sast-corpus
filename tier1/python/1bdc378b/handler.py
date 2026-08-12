import os


BASE = "/srv/reports"


def handle(name):
    if ".." in name:
        return ""
    target = os.path.join(BASE, name)
    with open(target) as handle_:
        return handle_.read()
