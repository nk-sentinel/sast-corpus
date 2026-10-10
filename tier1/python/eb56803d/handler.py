import traceback

from flask import Flask, request

from store import lookup

app = Flask(__name__)


@app.route("/show")
def show():
    try:
        return lookup(request.args.get("code", ""))
    except Exception:
        return traceback.format_exc()
