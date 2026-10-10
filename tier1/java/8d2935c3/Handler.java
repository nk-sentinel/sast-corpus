public final class Handler {
    public static String handle(String raw) {
        String code = raw.replaceAll("[^A-Z0-9]", "");
        if (!code.matches("^[A-Z0-9]{1,12}$")) {
            return "";
        }
        return run("SELECT status FROM orders WHERE code = '" + code + "'");
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
