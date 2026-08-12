public final class Tokens {
    private static final String SIGNING_KEY =
        System.getenv("JWT_SIGNING_KEY");

    public static String sign(String subject) {
        return subject + "." + SIGNING_KEY;
    }
}
