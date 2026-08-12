import Foundation

func render(_ raw: String) -> String {
    let count = Int32(raw) ?? 0
    let total = count &* 4096
    return "allocating \(total)"
}
