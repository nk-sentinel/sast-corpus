const CURRENT_USER: &str = "alice";

fn owner_of(order_id: &str) -> Option<&'static str> {
    match order_id {
        "A-1001" => Some("alice"),
        "A-1002" => Some("bob"),
        _ => None,
    }
}

pub fn render(order_id: &str) -> String {
    if owner_of(order_id) != Some(CURRENT_USER) {
        return String::new();
    }
    fetch_order(order_id)
}

fn fetch_order(order_id: &str) -> String {
    format!("order {} contents", order_id)
}
