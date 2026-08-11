package app

import java.net.URL

private val PERMITTED = setOf("api.example.com")

fun render(target: String): String {
    val parsed = URL(target)
    if (parsed.protocol != "https" || parsed.host !in PERMITTED) {
        throw IllegalArgumentException(target)
    }
    return parsed.readText()
}
