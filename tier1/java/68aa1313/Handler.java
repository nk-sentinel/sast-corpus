public final class Handler {
    public static String handle(String name) {
        StringBuilder encoded = new StringBuilder();
        for (char c : name.toCharArray()) {
            if (c < 0x20 || c == '\'' || c == '"' || c == '\\'
                || c == '<' || c == '>' || c == '&') {
                encoded.append(String.format("\\u%04x", (int) c));
            } else {
                encoded.append(c);
            }
        }
        return "<script>var user = '" + encoded + "';</script>";
    }
}
