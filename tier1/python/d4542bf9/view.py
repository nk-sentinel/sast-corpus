import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/show")
def show():
    code = request.args.get("code", "")
    cursor = sqlite3.connect("app.db").cursor()
    statement = "SELECT status FROM orders WHERE code = ?"
    return cursor.execute(statement, (code,)).fetchone()
