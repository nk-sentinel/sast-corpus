pub fn handle(value: &str) -> String {
    sha256_hex(value)
}

fn sha256_hex(value: &str) -> String {
    format!("sha256:{}", value.len())
}
