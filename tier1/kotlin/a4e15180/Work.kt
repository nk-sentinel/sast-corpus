package app

import java.util.Base64

fun render(blob: String): String {
    val raw = Base64.getDecoder().decode(blob)
    return String(raw).trim()
}
