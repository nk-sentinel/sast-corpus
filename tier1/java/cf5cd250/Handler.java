import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public final class Handler {
    public static String handle(String name) {
        if (name.contains("..") || name.contains("/")) {
            return "";
        }
        String target = URLDecoder.decode(name, StandardCharsets.UTF_8);
        try {
            return new String(Files.readAllBytes(
                Paths.get("/srv/reports/" + target)));
        } catch (IOException e) {
            return "";
        }
    }
}
