import sqlite3


def _run(statement):
    cursor = sqlite3.connect("app.db").cursor()
    return cursor.execute(statement).fetchone()


def show(code):
    return _run("SELECT status FROM orders WHERE code = '" + code + "'")
