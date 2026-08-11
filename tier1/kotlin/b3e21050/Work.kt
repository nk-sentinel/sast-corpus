package app

import java.io.File

private const val BASE = "/srv/reports"

fun render(name: String): String {
    return File(BASE, name).readText()
}
