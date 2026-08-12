import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public final class Report {
    public static String build(String name) {
        String target = name;
        try {
            return new String(Files.readAllBytes(
                Paths.get("/srv/reports/" + target)));
        } catch (IOException e) {
            return "";
        }
    }
}
