def build(code):
    holder = []
    same = holder
    holder.append(code)
    return run("SELECT status FROM orders WHERE code = '" + same[0] + "'")


def run(statement):
    return statement
