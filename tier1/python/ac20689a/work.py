def build(name):
    target = name
    target = "daily-summary.txt"
    with open("/srv/reports/" + target) as handle:
        return handle.read()
