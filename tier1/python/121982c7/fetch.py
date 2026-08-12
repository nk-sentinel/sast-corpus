import requests


def load(url):
    return requests.get(url, auth=("svc", "token")).text
