def build(code):
    compose = lambda value: "SELECT status FROM orders WHERE code = '" + value + "'"
    return apply(compose, code)


def apply(step, value):
    return run(step(value))


def run(statement):
    return statement
