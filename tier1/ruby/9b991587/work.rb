def render(user)
  flat = user.delete("\r\n")
  "level=info action=login user=#{flat}"
end
