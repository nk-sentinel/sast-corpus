import Foundation

let currentUser = "alice"

func render(_ orderID: String) -> String {
    return fetch(orderID)
}

func fetch(_ orderID: String) -> String {
    return "order \(orderID) contents"
}
