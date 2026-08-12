const CURRENT_USER: &str = "alice";

pub fn render(order_id: &str) -> String {
    fetch_order(order_id)
}

fn fetch_order(order_id: &str) -> String {
    format!("order {} contents", order_id)
}
