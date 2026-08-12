def build(code):
    compose = lambda value: "SELECT status FROM orders WHERE code = %s"
    return apply(compose, code)


def apply(step, value):
    return run(step(value), (value,))


def run(statement, params):
    return statement + "|" + str(params)
