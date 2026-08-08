package app

fun archive(name: String): String {
    val line = "tar -cf backup.tar " + name
    val process = ProcessBuilder("sh", "-c", line).start()
    return process.inputStream.readBytes().decodeToString()
}
