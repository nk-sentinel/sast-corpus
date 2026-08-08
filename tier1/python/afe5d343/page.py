import html


def render_row(name):
    return "<div class='row'>" + html.escape(name, quote=True) + "</div>"
