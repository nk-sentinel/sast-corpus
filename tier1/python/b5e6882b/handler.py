from flask import Flask, request

from loader import restore

app = Flask(__name__)


@app.route("/show")
def show():
    return restore(request.args.get("blob", ""))
