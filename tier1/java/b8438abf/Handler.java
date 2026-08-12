import java.net.URI;
import java.util.Arrays;
import java.util.List;

public final class Handler {
    private static final List<String> ALLOWED = Arrays.asList("api.example.com");

    public static String handle(String target) {
        URI uri = URI.create(target);
        if (!"https".equals(uri.getScheme()) || uri.getHost() == null
            || !ALLOWED.contains(uri.getHost())) {
            return "";
        }
        return fetch(uri);
    }

    private static String fetch(URI uri) {
        return uri.toString();
    }
}
