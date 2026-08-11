import Foundation

func render(_ target: String) -> String {
    guard let url = URL(string: target) else { return "" }
    return (try? String(contentsOf: url, encoding: .utf8)) ?? ""
}
