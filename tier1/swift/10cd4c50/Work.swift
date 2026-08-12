import Foundation

func render(_ raw: String) -> String {
    let count = Int32(raw) ?? 0
    let (total, overflowed) = count.multipliedReportingOverflow(by: 4096)
    if overflowed || total < 0 { return "rejected" }
    return "allocating \(total)"
}
