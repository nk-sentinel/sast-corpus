import os

DSN = "postgresql://reporting@db.internal:5432/orders"


def dsn():
    return DSN.replace("reporting@", "reporting:" + os.environ["DB_PASSWORD"] + "@")
