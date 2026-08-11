import os

UPLOADS = "/srv/uploads"
REFUSED = {".php", ".jsp", ".exe"}


def save(filename, payload):
    extension = os.path.splitext(filename)[1].lower()
    if extension in REFUSED:
        raise ValueError(filename)
    target = os.path.join(UPLOADS, filename)
    with open(target, "wb") as handle:
        handle.write(payload)
    return target
