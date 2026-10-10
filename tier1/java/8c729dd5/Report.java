public final class Report {
    public static String build(String code) {
        return run("SELECT status FROM orders WHERE code = ?", code);
    }

    private static String run(String statement, String value) {
        try (java.sql.Connection link = java.sql.DriverManager.getConnection("jdbc:sqlite:app.db");
             java.sql.PreparedStatement handle = link.prepareStatement(statement)) {
            handle.setString(1, value);
            return handle.executeQuery().getString(1);
        } catch (java.sql.SQLException failure) {
            return "";
        }
    }
}
