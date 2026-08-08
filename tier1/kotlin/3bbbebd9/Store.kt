package app

import java.sql.DriverManager

fun lookup(code: String): String {
    val connection = DriverManager.getConnection("jdbc:h2:mem:app")
    val statement = connection.createStatement()
    val results = statement.executeQuery("SELECT status FROM orders WHERE code = '" + code + "'")
    return if (results.next()) results.getString(1) else ""
}
