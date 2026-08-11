import Foundation

let base = "/srv/reports"

func render(_ name: String) -> String {
    let leaf = (name as NSString).lastPathComponent
    let target = (base as NSString).appendingPathComponent(leaf)
    guard target.hasPrefix(base + "/") else { return "" }
    return (try? String(contentsOfFile: target, encoding: .utf8)) ?? ""
}
