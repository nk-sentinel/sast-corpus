def render_row(name):
    cleaned = name.replace("<script>", "")
    return "<div class='row'>" + cleaned + "</div>"
