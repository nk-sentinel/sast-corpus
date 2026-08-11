import Foundation

func render(_ code: String) -> String {
    let statement = "SELECT status FROM orders WHERE code = ?"
    return execute(statement, code)
}

func execute(_ statement: String, _ value: String) -> String {
    return statement + "|" + value
}
