import Foundation

let permitted: Set<String> = ["api.example.com"]

func render(_ target: String) -> String {
    guard let url = URL(string: target), url.scheme == "https",
          let host = url.host, permitted.contains(host) else { return "" }
    return (try? String(contentsOf: url, encoding: .utf8)) ?? ""
}
