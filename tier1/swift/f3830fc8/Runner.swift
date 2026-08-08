import Foundation

func archive(_ name: String) -> String {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
    task.arguments = ["-cf", "backup.tar", name]
    try? task.run()
    return name
}
