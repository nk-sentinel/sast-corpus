const PERMITTED: [&str; 1] = ["api.example.com"];

pub fn handle(target: &str) -> String {
    if !target.starts_with("https://") {
        return String::new();
    }
    let host = target.trim_start_matches("https://").split('/').next().unwrap_or("");
    if !PERMITTED.contains(&host) {
        return String::new();
    }
    fetch(target)
}

fn fetch(target: &str) -> String {
    format!("GET {}", target)
}
