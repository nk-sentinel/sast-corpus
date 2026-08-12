import Foundation

enum StoreError: Error { case failed(String) }

func render(_ key: String) -> String {
    do {
        return try load(key)
    } catch {
        return "lookup failed"
    }
}

func load(_ key: String) throws -> String {
    throw StoreError.failed("connect to db.internal:5432 as reporting failed")
}
