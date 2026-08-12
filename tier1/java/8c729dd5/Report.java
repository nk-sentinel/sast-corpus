public final class Report {
    public static String build(String code) {
        return run("SELECT status FROM orders WHERE code = ?", code);
    }

    private static String run(String statement, String value) {
        return statement + "|" + value;
    }
}
