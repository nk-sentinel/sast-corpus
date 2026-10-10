def build(code):
    return run("SELECT status FROM orders WHERE code = %s", (code,))


def run(statement, params):
    import sqlite3

    cursor = sqlite3.connect("app.db").cursor()
    return cursor.execute(statement, params).fetchone()
