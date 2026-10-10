from flask import Flask, request

from page import render_row

app = Flask(__name__)


@app.route("/show")
def show():
    return render_row(request.args.get("name", ""))
