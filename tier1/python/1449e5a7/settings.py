import os

import psycopg2

DB_USER = os.environ["DB_USER"]
DB_PASSWORD = os.environ["DB_PASSWORD"]


def connect():
    return psycopg2.connect(user=DB_USER, password=DB_PASSWORD, host="db.internal")
