use std::fs;
use std::path::Path;

const BASE: &str = "/srv/reports";

pub fn contents(name: &str) -> String {
    let target = Path::new(BASE).join(name);
    fs::read_to_string(target).unwrap_or_default()
}
