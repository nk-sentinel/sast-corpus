import os


def handle(name):
    cleaned = os.path.basename(name)
    with open("/srv/reports/" + cleaned) as handle_:
        return handle_.read()
