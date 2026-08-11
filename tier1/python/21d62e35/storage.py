import os
import uuid

UPLOADS = "/srv/uploads"
PERMITTED = {".png", ".jpg", ".pdf"}


def save(filename, payload):
    extension = os.path.splitext(filename)[1].lower()
    if extension not in PERMITTED:
        raise ValueError(filename)
    target = os.path.join(UPLOADS, uuid.uuid4().hex + extension)
    with open(target, "wb") as handle:
        handle.write(payload)
    return target
