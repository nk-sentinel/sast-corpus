MAX_BYTES = 1048576


def receive(stream):
    payload = stream.read(MAX_BYTES + 1)
    if len(payload) > MAX_BYTES:
        raise ValueError("too large")
    return len(payload)
