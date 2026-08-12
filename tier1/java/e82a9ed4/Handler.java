public final class Handler {
    public static String handle(String name) {
        String encoded = name.replace("<", "&lt;").replace(">", "&gt;");
        return "<script>var user = '" + encoded + "';</script>";
    }
}
