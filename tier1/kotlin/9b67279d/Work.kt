const val CURRENT_USER = "alice"
val OWNERS = mapOf("A-1001" to "alice", "A-1002" to "bob")

fun render(orderId: String): String {
    if (OWNERS[orderId] != CURRENT_USER) return ""
    return fetchOrder(orderId)
}

fun fetchOrder(orderId: String): String = "order $orderId contents"
