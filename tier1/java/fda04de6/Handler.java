import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public final class Handler {
    public static String handle(String name) {
        try {
            Path target = Paths.get("/srv/reports/" + name);
            if (!target.startsWith("/srv/reports")) {
                return "";
            }
            return new String(Files.readAllBytes(target.toRealPath()));
        } catch (IOException e) {
            return "";
        }
    }
}
