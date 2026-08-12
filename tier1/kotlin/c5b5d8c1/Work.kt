fun render(key: String): String {
    return try {
        load(key)
    } catch (e: Exception) {
        "lookup failed"
    }
}

fun load(key: String): String {
    throw IllegalStateException("connect to db.internal:5432 as reporting failed")
}
