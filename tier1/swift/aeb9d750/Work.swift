import Foundation

func render(_ user: String) -> String {
    let password = ProcessInfo.processInfo.environment["DB_PASSWORD"] ?? ""
    return user + ":" + password
}
