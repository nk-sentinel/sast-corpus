def build(name):
    target = name
    with open("/srv/reports/" + target) as handle:
        return handle.read()
