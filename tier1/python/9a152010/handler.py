import urllib.parse
import urllib.request


ALLOWED = {"api.example.com"}


def handle(target):
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED:
        return ""
    with urllib.request.urlopen(target) as response:
        return response.read().decode("utf-8", "replace")
