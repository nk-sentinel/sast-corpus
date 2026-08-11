import Foundation

let base = "/srv/reports"

func render(_ name: String) -> String {
    let target = base + "/" + name
    return (try? String(contentsOfFile: target, encoding: .utf8)) ?? ""
}
