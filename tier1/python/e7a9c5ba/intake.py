def receive(stream):
    payload = stream.read()
    return len(payload)
