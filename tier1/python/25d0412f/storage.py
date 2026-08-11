import os

UPLOADS = "/srv/uploads"


def save(filename, payload):
    target = os.path.join(UPLOADS, filename)
    with open(target, "wb") as handle:
        handle.write(payload)
    return target
