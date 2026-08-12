public final class Handler {
    public static String handle(String name) {
        StringBuilder encoded = new StringBuilder();
        for (char c : name.toCharArray()) {
            switch (c) {
                case '<': encoded.append("&lt;"); break;
                case '>': encoded.append("&gt;"); break;
                case '&': encoded.append("&amp;"); break;
                case '"': encoded.append("&quot;"); break;
                case '\'': encoded.append("&#x27;"); break;
                default: encoded.append(c);
            }
        }
        return "<div>" + encoded + "</div>";
    }
}
