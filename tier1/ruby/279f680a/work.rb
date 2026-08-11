require 'digest'

def render(value)
  Digest::MD5.hexdigest(value)
end
