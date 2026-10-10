from flask import Flask, request

from runner import archive

app = Flask(__name__)


@app.route("/show")
def show():
    return archive(request.args.get("name", ""))
