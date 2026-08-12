public final class Handler {
    public static String handle(String name) {
        String[] parts = name.split(",", 2);
        String code = parts[0].replace("'", "''");
        String order = parts.length > 1 ? parts[1] : "code";
        return run("SELECT status FROM orders WHERE code = '" + code
                   + "' ORDER BY " + order);
    }

    private static String run(String statement) {
        return statement;
    }
}
