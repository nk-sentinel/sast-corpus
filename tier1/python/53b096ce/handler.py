import re
import urllib.request


ALLOWED = re.compile(r"api\.example\.com")


def handle(target):
    if not ALLOWED.search(target):
        return ""
    with urllib.request.urlopen(target) as response:
        return response.read().decode("utf-8", "replace")
