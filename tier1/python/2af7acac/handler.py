import html


def handle(name):
    encoded = html.escape(name, quote=False)
    return "<div title=" + encoded + ">report</div>"
