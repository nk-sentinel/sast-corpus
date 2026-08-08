use std::process::Command;

pub fn archive(name: &str) -> String {
    let out = Command::new("tar").args(["-cf", "backup.tar", name]).output().unwrap();
    String::from_utf8_lossy(&out.stdout).to_string()
}
