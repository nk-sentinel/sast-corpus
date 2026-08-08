import psycopg2

DB_USER = "reporting"
DB_PASSWORD = "Pr0d-Repor7ing-2024!"


def connect():
    return psycopg2.connect(user=DB_USER, password=DB_PASSWORD, host="db.internal")
