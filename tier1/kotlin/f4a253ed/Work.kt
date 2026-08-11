package app

fun render(user: String): String = "$user:" + (System.getenv("DB_PASSWORD") ?: "")
