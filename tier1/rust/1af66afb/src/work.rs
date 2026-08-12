pub fn render(user: &str) -> String {
    let flat: String = user.chars().filter(|c| *c != '\n' && *c != '\r').collect();
    format!("level=info action=login user={}", flat)
}
