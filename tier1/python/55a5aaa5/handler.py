def handle(name):
    name.replace("..", "")
    with open("/srv/reports/" + name) as handle_:
        return handle_.read()
