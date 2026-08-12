public final class Handler {
    public static String handle(String name) {
        String cleaned = name.replace("<script>", "").replace("</script>", "");
        return "<div>" + cleaned + "</div>";
    }
}
