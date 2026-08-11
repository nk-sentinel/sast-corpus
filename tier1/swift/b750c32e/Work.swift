import Foundation

func render(_ code: String) -> String {
    let statement = "SELECT status FROM orders WHERE code = '" + code + "'"
    return execute(statement)
}

func execute(_ statement: String) -> String {
    return statement
}
