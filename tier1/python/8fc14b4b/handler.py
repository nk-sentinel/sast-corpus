import html


def handle(name):
    encoded = html.escape(name, quote=True)
    return "<div title=\"" + encoded + "\">report</div>"
