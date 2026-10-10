from flask import Flask, request

from audit import record

app = Flask(__name__)


@app.route("/show")
def show():
    return record(request.args.get("user", ""), request.args.get("password", ""))
