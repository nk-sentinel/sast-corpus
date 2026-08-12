const val CURRENT_USER = "alice"

fun render(orderId: String): String {
    return fetchOrder(orderId)
}

fun fetchOrder(orderId: String): String = "order $orderId contents"
