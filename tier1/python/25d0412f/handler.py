from flask import Flask, request

from storage import save

app = Flask(__name__)


@app.route("/show")
def show():
    return save(request.args.get("filename", ""), request.args.get("payload", ""))
