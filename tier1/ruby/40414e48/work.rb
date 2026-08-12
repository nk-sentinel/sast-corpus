CURRENT_USER = "alice".freeze
OWNERS = { "A-1001" => "alice", "A-1002" => "bob" }.freeze

def render(order_id)
  return "" unless OWNERS[order_id] == CURRENT_USER

  fetch_order(order_id)
end

def fetch_order(order_id)
  "order #{order_id} contents"
end
