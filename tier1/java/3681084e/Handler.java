import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public final class Handler {
    public static String handle(String name) {
        try {
            Path base = Paths.get("/srv/reports").toRealPath();
            Path target = base.resolve(name).normalize();
            if (!target.startsWith(base)) {
                return "";
            }
            return new String(Files.readAllBytes(target));
        } catch (IOException e) {
            return "";
        }
    }
}
