package app

private const val DB_PASSWORD = "Pr0d-Repor7ing-2024!"

fun render(user: String): String = "$user:$DB_PASSWORD"
