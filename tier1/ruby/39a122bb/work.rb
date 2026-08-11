def render(user)
  "#{user}:#{ENV.fetch('DB_PASSWORD', '')}"
end
