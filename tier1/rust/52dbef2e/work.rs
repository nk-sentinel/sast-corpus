pub fn handle(code: &str) -> String {
    let statement = format!("SELECT status FROM orders WHERE code = '{}'", code);
    run(&statement)
}

fn run(statement: &str) -> String {
    statement.to_string()
}
