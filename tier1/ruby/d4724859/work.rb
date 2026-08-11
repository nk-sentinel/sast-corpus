require 'cgi'

def render(name)
  "<div class='row'>" + CGI.escapeHTML(name) + '</div>'
end
