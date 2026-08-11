pub fn handle(user: &str) -> String {
    let password = std::env::var("DB_PASSWORD").unwrap_or_default();
    format!("{}:{}", user, password)
}
