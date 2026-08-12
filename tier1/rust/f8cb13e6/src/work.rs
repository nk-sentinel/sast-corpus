pub fn render(raw: &str) -> String {
    let table = [10u8, 20, 30, 40];
    let index: usize = raw.parse().unwrap_or(0);
    match table.get(index) {
        Some(value) => format!("{}", value),
        None => String::new(),
    }
}
