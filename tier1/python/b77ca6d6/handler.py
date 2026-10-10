from flask import Flask, request

from ledger import total

app = Flask(__name__)


@app.route("/show")
def show():
    return total(int(request.args.get("quantity", "0")))
