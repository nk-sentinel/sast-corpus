require 'digest'

def render(value)
  Digest::SHA256.hexdigest(value)
end
