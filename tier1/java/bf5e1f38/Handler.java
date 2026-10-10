public final class Handler {
    public static String handle(String name) {
        String[] parts = name.split(",", 2);
        String code = parts[0].replace("'", "''");
        String order = parts.length > 1 ? parts[1] : "code";
        return run("SELECT status FROM orders WHERE code = '" + code
                   + "' ORDER BY " + order);
    }

    private static String run(String statement) {
        try (java.sql.Connection link = java.sql.DriverManager.getConnection("jdbc:sqlite:app.db");
             java.sql.Statement handle = link.createStatement()) {
            return handle.executeQuery(statement).getString(1);
        } catch (java.sql.SQLException failure) {
            return "";
        }
    }
}
