import java.util.function.Function;

public final class Report {
    public static String build(String code) {
        Function<String, String> compose =
            value -> "SELECT status FROM orders WHERE code = ?";
        return apply(compose, code);
    }

    private static String apply(Function<String, String> step, String value) {
        return run(step.apply(value), value);
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
