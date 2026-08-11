import os

TOKEN = os.environ["GITHUB_TOKEN"]


def headers():
    return {"Authorization": "token " + TOKEN}
