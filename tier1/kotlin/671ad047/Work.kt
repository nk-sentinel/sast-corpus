package app

import java.net.URL

fun render(target: String): String {
    return URL(target).readText()
}
