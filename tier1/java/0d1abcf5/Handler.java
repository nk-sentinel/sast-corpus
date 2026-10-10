import java.util.Arrays;
import java.util.List;

public final class Handler {
    private static final List<String> COLUMNS = Arrays.asList("code", "status");

    public static String handle(String name) {
        String[] parts = name.split(",", 2);
        String order = parts.length > 1 ? parts[1] : "code";
        if (!COLUMNS.contains(order)) {
            return "";
        }
        return run("SELECT status FROM orders WHERE code = ? ORDER BY " + order,
                   parts[0]);
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
