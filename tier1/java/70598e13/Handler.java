public final class Handler {
    public static String handle(String raw) {
        String code = raw.replaceAll("[^A-Z0-9]", "");
        if (!code.matches("^[A-Z0-9]{1,12}$")) {
            return "";
        }
        return run("SELECT status FROM orders WHERE code = '" + raw + "'");
    }

    private static String run(String statement) {
        return statement;
    }
}
