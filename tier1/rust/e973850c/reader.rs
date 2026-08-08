use std::fs;
use std::path::Path;

const BASE: &str = "/srv/reports";

pub fn contents(name: &str) -> String {
    let leaf = match Path::new(name).file_name() {
        Some(value) => value.to_owned(),
        None => return String::new(),
    };
    let target = Path::new(BASE).join(leaf);
    fs::read_to_string(target).unwrap_or_default()
}
