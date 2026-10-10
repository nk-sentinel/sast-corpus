import Foundation
import SQLite3

func render(_ code: String) -> String {
    let statement = "SELECT status FROM orders WHERE code = '" + code + "'"
    return execute(statement)
}

func execute(_ statement: String) -> String {
    var handle: OpaquePointer?
    sqlite3_open("app.db", &handle)
    sqlite3_exec(handle, statement, nil, nil, nil)
    sqlite3_close(handle)
    return statement
}
