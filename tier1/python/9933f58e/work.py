def build(code):
    return run("SELECT status FROM orders WHERE code = %s", (code,))


def run(statement, params):
    return statement + "|" + str(params)
