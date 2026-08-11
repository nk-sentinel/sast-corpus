BASE = '/srv/reports'.freeze

def render(name)
  target = File.expand_path(File.join(BASE, File.basename(name)))
  raise ArgumentError, name unless target.start_with?(BASE + '/')

  File.read(target)
end
