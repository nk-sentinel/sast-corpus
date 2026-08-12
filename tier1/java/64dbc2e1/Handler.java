import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public final class Handler {
    public static String handle(String name) {
        String cleaned = Paths.get(name).getFileName().toString();
        try {
            return new String(Files.readAllBytes(
                Paths.get("/srv/reports/" + cleaned)));
        } catch (IOException e) {
            return "";
        }
    }
}
