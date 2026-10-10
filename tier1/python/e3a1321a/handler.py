from flask import Flask, request

from reader import contents

app = Flask(__name__)


@app.route("/show")
def show():
    return contents(request.args.get("name", ""))
