public final class Tokens {
    private static final String SIGNING_KEY =
        "hV8kQ2mNvB7xJ4pL9wT6yD3nH5sG1fA0zZcXe2iOnQ7kR3mB9wT4yD6nH2sG8f";

    public static String sign(String subject) {
        return subject + "." + SIGNING_KEY;
    }
}
