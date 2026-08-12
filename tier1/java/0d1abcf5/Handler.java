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
        return statement + "|" + value;
    }
}
