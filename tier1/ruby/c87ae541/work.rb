CURRENT_USER = "alice".freeze

def render(order_id)
  fetch_order(order_id)
end

def fetch_order(order_id)
  "order #{order_id} contents"
end
