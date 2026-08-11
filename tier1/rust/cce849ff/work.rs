pub fn handle(target: &str) -> String {
    fetch(target)
}

fn fetch(target: &str) -> String {
    format!("GET {}", target)
}
