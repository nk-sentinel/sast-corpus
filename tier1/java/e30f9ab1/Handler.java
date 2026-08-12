import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public final class Handler {
    public static String handle(String name) {
        String target = URLDecoder.decode(name, StandardCharsets.UTF_8);
        if (target.contains("..") || target.contains("/")) {
            return "";
        }
        try {
            return new String(Files.readAllBytes(
                Paths.get("/srv/reports/" + target)));
        } catch (IOException e) {
            return "";
        }
    }
}
