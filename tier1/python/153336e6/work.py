class Request:
    def __init__(self):
        self.name = None


def build(name):
    request = Request()
    request.name = name
    return read(request)


def read(request):
    with open("/srv/reports/" + request.name) as handle:
        return handle.read()
