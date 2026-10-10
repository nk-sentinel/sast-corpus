def build(code):
    holder = []
    same = holder
    holder.append(code)
    return run("SELECT status FROM orders WHERE code = '" + same[0] + "'")


def run(statement):
    import sqlite3

    cursor = sqlite3.connect("app.db").cursor()
    return cursor.execute(statement).fetchone()
