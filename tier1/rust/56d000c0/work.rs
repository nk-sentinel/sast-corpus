pub fn handle(value: &str) -> String {
    md5_hex(value)
}

fn md5_hex(value: &str) -> String {
    format!("md5:{}", value.len())
}
