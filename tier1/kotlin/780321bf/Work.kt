package app

import java.security.MessageDigest

fun render(value: String): String {
    val digest = MessageDigest.getInstance("MD5")
    return digest.digest(value.toByteArray()).joinToString("") { "%02x".format(it) }
}
