import java.util.function.Function;

public final class Report {
    public static String build(String code) {
        Function<String, String> compose =
            value -> "SELECT status FROM orders WHERE code = '" + value + "'";
        return apply(compose, code);
    }

    private static String apply(Function<String, String> step, String value) {
        return run(step.apply(value));
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
