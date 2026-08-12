import os


BASE = "/srv/reports"


class Request:
    def __init__(self):
        self.name = None


def build(name):
    request = Request()
    request.name = os.path.basename(name)
    return read(request)


def read(request):
    target = os.path.realpath(os.path.join(BASE, request.name))
    if not target.startswith(BASE + os.sep):
        return ""
    with open(target) as handle:
        return handle.read()
