from flask import Flask, request

from fetcher import body

app = Flask(__name__)


@app.route("/show")
def show():
    return body(request.args.get("target", ""))
