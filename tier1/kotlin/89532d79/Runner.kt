package app

fun archive(name: String): String {
    val process = ProcessBuilder(listOf("tar", "-cf", "backup.tar", name)).start()
    return process.inputStream.readBytes().decodeToString()
}
