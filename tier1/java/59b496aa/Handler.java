import java.net.URI;
import java.util.regex.Pattern;

public final class Handler {
    private static final Pattern HOST = Pattern.compile("api.example.com");

    public static String handle(String target) {
        if (!HOST.matcher(target).find()) {
            return "";
        }
        return fetch(URI.create(target));
    }

    private static String fetch(URI uri) {
        return uri.toString();
    }
}
