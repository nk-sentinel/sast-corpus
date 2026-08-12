import Foundation

func render(_ user: String) -> String {
    let flat = user.replacingOccurrences(of: "\n", with: "")
        .replacingOccurrences(of: "\r", with: "")
    return "level=info action=login user=" + flat
}
