import Foundation

let value = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ""
print(render(value))
