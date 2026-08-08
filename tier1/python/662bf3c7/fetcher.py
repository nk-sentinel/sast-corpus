import requests


def body(target):
    response = requests.get(target, timeout=5)
    return response.text
