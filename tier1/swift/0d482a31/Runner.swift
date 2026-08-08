import Foundation

func archive(_ name: String) -> String {
    let line = "tar -cf backup.tar " + name
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/bin/sh")
    task.arguments = ["-c", line]
    try? task.run()
    return line
}
