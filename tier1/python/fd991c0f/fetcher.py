from urllib.parse import urlparse

import requests

PERMITTED = {"api.example.com", "cdn.example.com"}


def body(target):
    parsed = urlparse(target)
    if parsed.scheme != "https" or parsed.hostname not in PERMITTED:
        raise ValueError(target)
    response = requests.get(target, timeout=5)
    return response.text
