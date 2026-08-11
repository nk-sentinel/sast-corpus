package app

import java.io.File

private const val BASE = "/srv/reports"

fun render(name: String): String {
    val target = File(BASE, File(name).name).canonicalFile
    if (!target.path.startsWith("$BASE/")) {
        throw IllegalArgumentException(name)
    }
    return target.readText()
}
