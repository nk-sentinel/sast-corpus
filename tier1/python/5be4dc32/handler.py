from flask import Flask, request

from store import lookup

app = Flask(__name__)


@app.route("/show")
def show():
    return lookup(request.args.get("code", ""))
