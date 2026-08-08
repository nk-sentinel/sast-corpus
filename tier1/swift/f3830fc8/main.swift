import Foundation

let name = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ""
print(archive(name))
