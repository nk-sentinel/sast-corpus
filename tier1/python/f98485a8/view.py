import sqlite3

from flask import Flask, request

app = Flask(__name__)


def _run(statement, code):
    cursor = sqlite3.connect("app.db").cursor()
    return cursor.execute(statement, (code,)).fetchone()


@app.route("/show")
def show():
    code = request.args.get("code", "")
    return _run("SELECT status FROM orders WHERE code = ?", code)
