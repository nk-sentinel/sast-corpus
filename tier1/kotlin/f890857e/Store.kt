package app

import java.sql.DriverManager

fun lookup(code: String): String {
    val connection = DriverManager.getConnection("jdbc:h2:mem:app")
    val statement = connection.prepareStatement("SELECT status FROM orders WHERE code = ?")
    statement.setString(1, code)
    val results = statement.executeQuery()
    return if (results.next()) results.getString(1) else ""
}
