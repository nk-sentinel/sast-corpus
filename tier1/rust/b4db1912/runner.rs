use std::process::Command;

pub fn archive(name: &str) -> String {
    let line = format!("tar -cf backup.tar {}", name);
    let out = Command::new("sh").arg("-c").arg(line).output().unwrap();
    String::from_utf8_lossy(&out.stdout).to_string()
}
