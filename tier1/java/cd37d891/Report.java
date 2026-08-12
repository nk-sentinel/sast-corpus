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
        return statement + "|" + value;
    }
}
