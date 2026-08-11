const DB_PASSWORD: &str = "Pr0d-Repor7ing-2024!";

pub fn handle(user: &str) -> String {
    format!("{}:{}", user, DB_PASSWORD)
}
