from flask import Flask, request

from intake import receive

app = Flask(__name__)


@app.route("/show")
def show():
    return receive(request.args.get("stream", ""))
