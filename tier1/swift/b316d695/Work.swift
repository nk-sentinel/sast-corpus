import Foundation

let currentUser = "alice"
let owners = ["A-1001": "alice", "A-1002": "bob"]

func render(_ orderID: String) -> String {
    guard owners[orderID] == currentUser else { return "" }
    return fetch(orderID)
}

func fetch(_ orderID: String) -> String {
    return "order \(orderID) contents"
}
