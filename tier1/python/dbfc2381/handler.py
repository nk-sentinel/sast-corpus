import re


def handle(raw):
    code = re.sub(r"[^A-Z0-9]", "", raw)
    if not re.fullmatch(r"[A-Z0-9]{1,12}", code):
        return ""
    return run("SELECT status FROM orders WHERE code = '" + raw + "'")


def run(statement):
    import sqlite3

    cursor = sqlite3.connect("app.db").cursor()
    return cursor.execute(statement).fetchone()
