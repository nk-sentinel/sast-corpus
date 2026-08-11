BASE = '/srv/reports'.freeze

def render(name)
  File.read(File.join(BASE, name))
end
