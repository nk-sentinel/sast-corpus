pub fn handle(code: &str) -> String {
    let statement = "SELECT status FROM orders WHERE code = $1";
    run(statement, code)
}

fn run(statement: &str, code: &str) -> String {
    format!("{}|{}", statement, code)
}
