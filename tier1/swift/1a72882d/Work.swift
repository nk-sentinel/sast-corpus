import Foundation
import SQLite3

func render(_ code: String) -> String {
    let statement = "SELECT status FROM orders WHERE code = ?"
    return execute(statement, code)
}

func execute(_ statement: String, _ value: String) -> String {
    var handle: OpaquePointer?
    sqlite3_open("app.db", &handle)
    var stmt: OpaquePointer?
    sqlite3_prepare_v2(handle, statement, -1, &stmt, nil)
    sqlite3_bind_text(stmt, 1, value, -1, nil)
    sqlite3_step(stmt)
    sqlite3_close(handle)
    return statement
}
