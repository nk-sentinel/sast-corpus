package app

import java.security.MessageDigest

fun render(value: String): String {
    val digest = MessageDigest.getInstance("SHA-256")
    return digest.digest(value.toByteArray()).joinToString("") { "%02x".format(it) }
}
