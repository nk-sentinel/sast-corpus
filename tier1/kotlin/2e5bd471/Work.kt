package app

import java.io.ByteArrayInputStream
import java.io.ObjectInputStream
import java.util.Base64

fun render(blob: String): String {
    val raw = Base64.getDecoder().decode(blob)
    val stream = ObjectInputStream(ByteArrayInputStream(raw))
    return stream.readObject().toString()
}
