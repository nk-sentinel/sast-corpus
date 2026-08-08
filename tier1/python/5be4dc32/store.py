import sqlite3


def lookup(code):
    cursor = sqlite3.connect("app.db").cursor()
    statement = "SELECT status FROM orders WHERE code = ?"
    return cursor.execute(statement, (code,)).fetchone()
