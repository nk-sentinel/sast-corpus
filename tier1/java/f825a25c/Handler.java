import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public final class Handler {
    public static String handle(String name) {
        name.replace("..", "");
        try {
            return new String(Files.readAllBytes(
                Paths.get("/srv/reports/" + name)));
        } catch (IOException e) {
            return "";
        }
    }
}
